use std::{str::{FromStr}, collections::HashMap, sync::Arc};

use anyhow::{anyhow, Result};
use deadpool_postgres::{Manager, ManagerConfig, Object, Pool as PgPool, RecyclingMethod};
use deadpool_redis::{Config as RConf, Connection, Pool as RedisPool, Runtime};use serde_derive::{Serialize, Deserialize};
use openssl::ssl::{SslConnector, SslMethod};
use postgres_openssl::MakeTlsConnector;
use tokio::{try_join, sync::RwLock};
use tokio_postgres::{Config as PgConf, NoTls};
use google_secretmanager1::{oauth2::{ServiceAccountKey, ServiceAccountAuthenticator}, SecretManager, hyper_rustls, hyper::Client};


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

pub async fn get_pg_conf(sa: &ServiceAccountKey, db: &str) -> Result<tokio_postgres::Config> {
    let cxn = get_cxn_secret(sa, db).await?;
    Ok(PgConf::from_str(cxn.replace("verify-full", "require").as_str())?)
}

pub async fn get_redis_conf(sa: &ServiceAccountKey) -> Result<deadpool_redis::Config> {
    let cxn = get_cxn_secret(sa, "cache").await?;
    Ok(RConf::from_url(cxn))
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

// returns the connection string as a secret
pub async fn get_cxn_secret(secret: &ServiceAccountKey, db: &str) -> Result<String> {
    let auth = ServiceAccountAuthenticator::builder(secret.clone()).build().await?;
    let hub = SecretManager::new(
            Client::builder().build(
                hyper_rustls::HttpsConnectorBuilder::new()
                .with_native_roots()
                .https_or_http()
                .enable_http1()
                .enable_http2()
                .build()), auth);
    
    let secret_name = format!("projects/xambit-1/secrets/db-cxn-{db}");
    let (_, s) = hub.projects().secrets_versions_access(&secret_name).doit().await?;
    
    let secret = if let Some(pl) = s.payload && let Some(d) = pl.data {
        base64::decode(d.as_bytes())?
    } else {
        return Err(anyhow!("Invalid db credentials"));
    };


    Ok(String::from_utf8(secret)?)
}

pub struct Db {
    sa: ServiceAccountKey,
    // gcs: GClient,
    xai: PgPool,
    orgpg: Arc<RwLock<HashMap<String, PgPool>>>,
    redis: RedisPool,
}

impl Db {
    pub async fn new(sa: ServiceAccountKey) -> Result<Self> {
        // let gcs = GClient::default();
        // let c = get_db_conf(&gcs, "xai.db").await?;
        let (xai, redis) = try_join!(
            Self::connect_xai_pg(&sa),
            Self::connect_redis(&sa)
        )?;

        // create client connection for sentry gRPC here and get session from there
        // and return Ok((true, Session))
        Ok(Self {
            sa,
            // gcs,
            xai,
            orgpg: Arc::new(RwLock::new(HashMap::new())),
            redis,
        })
    }

    async fn connect_xai_pg(sa: &ServiceAccountKey) -> Result<PgPool> {
        connect_pg(get_pg_conf(sa, "xai").await?, 4, true)
    }

    pub async fn get_xai_pg(&self) -> Result<Object> {
        if let Ok(p) = self.xai.get().await {
            Ok(p)
        } else {
            Err(anyhow!("failed to get xai.pg"))
        }
    }

    async fn connect_redis(sa: &ServiceAccountKey) -> Result<RedisPool> {
        // if let (Some(pwd), Some(host), Some(port)) = (&c.pwd, &c.host, &c.port) {
            // let cfg = RConf::from_url(format!("redis://:{}@{}:{}", pwd, host, port));
        let cfg = get_redis_conf(sa).await?;

        let pool = cfg.create_pool(Some(Runtime::Tokio1))?;
         
        Ok(pool)
        // } else {
        //     Err(anyhow!("Invalid redis creds"))
        // }
    }

    pub async fn ensure_tenant_db(&self, org: &str) -> Result<()> {
        {
            let p = self.orgpg.read().await;
            if p.contains_key(org) {
                return Ok(());
            }
        }

        let p = Self::connect_tenant_pg(&self.sa, org).await?;
        let mut l = self.orgpg.write().await;
        l.insert(org.to_owned(), p);

        Ok(())
    }

    async fn connect_tenant_pg(sa: &ServiceAccountKey, org: &str) -> Result<PgPool> {
        let pool = connect_pg(
            get_pg_conf(sa, org.replace("o-", "db").to_lowercase().as_str()).await?,
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

#[cfg(test)]
mod tests {
    // use std::env;

    // use anyhow::Result;
    // use google_secretmanager1::oauth2::ServiceAccountKey;
    // use tokio::fs::read_to_string;

    // async fn get_service_account() -> Result<ServiceAccountKey> {

    //     let f = if let Ok(s) = env::var("SERVICE_ACCOUNT_JSON") {
    //         s
    //     } else {
    //         let safile = env::var("SERVICE_ACCOUNT")?;
    //         read_to_string(&safile).await?
    //     };

    //     Ok(serde_json::from_str::<ServiceAccountKey>(&f)?)
    // }
}