use std::{str::FromStr, collections::HashMap, sync::Arc};

use anyhow::{anyhow, Result};
use cloud_storage::Client as GClient;
use deadpool_postgres::{Manager, ManagerConfig, Object, Pool as PgPool, RecyclingMethod};
use deadpool_redis::{Config as RConf, Connection, Pool as RedisPool, Runtime};use serde_derive::{Serialize, Deserialize};
use openssl::ssl::{SslConnector, SslMethod};
use postgres_openssl::MakeTlsConnector;
use tokio::{try_join, sync::RwLock};
use tokio_postgres::{Config as PgConf, NoTls};


#[derive(Serialize, Deserialize)]
pub struct DbConf {
    pgsql: DbDef,
    redis: DbDef,
}

#[derive(Serialize, Deserialize)]
pub struct DbDef {
    host: Option<String>,
    port: Option<u16>,
    user: Option<String>,
    pwd: Option<String>,
    cockroach: Option<String>,
}

pub async fn get_db_conf(c: &GClient, key: &str) -> Result<DbConf> {
    let o = c.object().download("xai-cfg", key).await?;

    let d: DbConf = serde_json::from_slice(&o)?;

    Ok(d)
}

pub async fn get_pg_conf(db: &str, c: &DbDef) -> Result<tokio_postgres::Config> {
    if let Some(cstr) = &c.cockroach {
        Ok(PgConf::from_str(cstr.replace("verify-full", "require").as_str())?)
    } else {
        let mut cfg = PgConf::new();
        cfg.dbname(db);
        if let Some(n) = &c.user {
            cfg.user(n);
        }
        if let Some(p) = &c.pwd {
            cfg.password(p);
        }
        if let Some(h) = &c.host {
            cfg.host(h);
        }
        if let Some(p) = &c.port {
            cfg.port(*p);
        }

        Ok(cfg)
    }
}

pub fn connect_pg(cfg: tokio_postgres::Config, pool_size: usize, isroach: bool) -> Result<PgPool> {
    let mgr_config = ManagerConfig {
        recycling_method: RecyclingMethod::Fast,
    };

    let mgr = if isroach {
        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_ca_file("roach.crt")?;
        let connector = MakeTlsConnector::new(builder.build());
        Manager::from_config(cfg, connector, mgr_config)
        // let mut builder = Tls::builder(::tls()).expect("unable to create sslconnector builder");
    } else {
        Manager::from_config(cfg, NoTls, mgr_config)
    };
    let pool = PgPool::builder(mgr).max_size(pool_size).build()?;

    Ok(pool)
}

pub struct Db {
    gcs: GClient,
    xai: PgPool,
    orgpg: Arc<RwLock<HashMap<String, PgPool>>>,
    // orgmg:Arc<RwLock<HashMap<String, ()>>>,
    redis: RedisPool,
}

impl Db {
    pub async fn new() -> Result<Self> {
        let gcs = GClient::default();
        let c = get_db_conf(&gcs, "xai.db").await?;
        let (xai, redis) = try_join!(
            Self::connect_xai_pg(&c.pgsql),
            Self::connect_redis(&c.redis)
        )?;

        // create client connection for sentry gRPC here and get session from there
        // and return Ok((true, Session))
        Ok(Self {
            gcs,
            xai,
            orgpg: Arc::new(RwLock::new(HashMap::new())),
            // orgmg: Arc::new(RwLock::new(HashMap::new())),
            redis,
        })
    }

    async fn connect_xai_pg(c: &DbDef) -> Result<PgPool> {
        let pool = connect_pg(get_pg_conf("xai", c).await?, 4, true)?;

        // making sure a bad connection crashes
        {
            let _ = pool.get().await?;
        }

        Ok(pool)
    }

    pub async fn get_xai_pg(&self) -> Result<Object> {
        if let Ok(p) = self.xai.get().await {
            Ok(p)
        } else {
            Err(anyhow!("failed to get xai.pg"))
        }
    }

    async fn connect_redis(c: &DbDef) -> Result<RedisPool> {
        if let (Some(pwd), Some(host), Some(port)) = (&c.pwd, &c.host, &c.port) {
            let cfg = RConf::from_url(format!("redis://:{}@{}:{}", pwd, host, port));
            let pool = cfg.create_pool(Some(Runtime::Tokio1))?;
         
            Ok(pool)
        } else {
            Err(anyhow!("Invalid redis creds"))
        }
    }

    pub async fn ensure_tenant_db(&self, org: &str) -> Result<()> {
        {
            let p = self.orgpg.read().await;
            if p.contains_key(org) {
                return Ok(());
            }
        }

        let f = get_db_conf(&self.gcs, format!("creds/{org}.db").as_str()).await?;
        let p = Self::connect_tenant_pg(org, &f.pgsql).await?;
        let mut l = self.orgpg.write().await;
        l.insert(org.to_owned(), p);

        Ok(())
    }

    async fn connect_tenant_pg(org: &str, conf: &DbDef) -> Result<PgPool> {
        let pool = connect_pg(
            get_pg_conf(org.replace("o-", "db").to_lowercase().as_str(), conf).await?,
            2,
            false,
        )?;

        // making sure a bad connection crashes
        {
            let _ = pool.get().await?;
        }

        Ok(pool)
    }

    pub async fn get_tenant_pg(&self, org: &str) -> Result<Object> {
        self.ensure_tenant_db(org).await?;

        let db = {
            let o = self.orgpg.read().await;
            if let Some(d) = o.get(org) &&
            let Ok(p) = d.get().await {
                p
            } else {
                return Err(anyhow!("while getting tenant db[{}]",org));
            }
        };
        Ok(db)
    }

    pub async fn get_redis(&self) -> Result<Connection> {
        Ok(self.redis.get().await?)
    }
}