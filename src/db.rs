use std::{collections::HashMap, env, fs::remove_file, path::Path, str::FromStr, sync::Arc};

use anyhow::{anyhow, Result};
use deadpool_postgres::{Manager, ManagerConfig, Object, Pool as PgPool};
use deadpool_redis::{redis::cmd, Config as RConf, Connection, Pool as RedisPool, Runtime};
use google_auth_helper::AuthHelper;
use nimbus::{Authenticator, SecretManager, SecretManagerHelper};
use openssl::ssl::{SslConnector, SslConnectorBuilder, SslMethod};
use passwords::PasswordGenerator;
use postgres_openssl::MakeTlsConnector;
use serde::Serialize;
use tokio::{fs::write, sync::RwLock, try_join};
use tokio_postgres::{Config as PgConf, NoTls};

pub async fn generate_password(len: usize) -> Result<String> {
    let pwd = PasswordGenerator {
        length: len,
        lowercase_letters: true,
        numbers: true,
        symbols: false,
        uppercase_letters: true,
        spaces: false,
        exclude_similar_characters: false,
        strict: true,
    };

    match pwd.generate_one() {
        Ok(s) => Ok(s),
        Err(e) => Err(anyhow!(e)),
    }
}

pub async fn get_pg_conf(project: &str, db: &str) -> Result<tokio_postgres::Config> {
    let cxn = get_cxn_secret(project, db).await?;
    Ok(PgConf::from_str(
        cxn.replace("verify-full", "require").as_str(),
    )?)
}

pub async fn get_redis_conf(project: &str, isdev: bool) -> Result<deadpool_redis::Config> {
    let secretname = if isdev { "dev-cache" } else { "cache" };
    let cxn = get_cxn_secret(project, secretname).await?;

    Ok(RConf::from_url(cxn))
}

pub async fn connect_pg(
    project: &str,
    cfg: tokio_postgres::Config,
    pool_size: usize,
    isroach: bool,
    cert: &str,
) -> Result<PgPool> {
    let mgr_cfg = ManagerConfig::default();

    let mgr = if isroach {
        let mut builder = SslConnector::builder(SslMethod::tls())?;
        cert_it(project, &mut builder, cert).await?;

        let connector = MakeTlsConnector::new(builder.build());
        Manager::from_config(cfg, connector, mgr_cfg)
        // let mut builder = Tls::builder(::tls()).expect("unable to create sslconnector builder");
    } else {
        Manager::from_config(cfg, NoTls, mgr_cfg)
    };
    let pool = PgPool::builder(mgr).max_size(pool_size).build()?;

    Ok(pool)
}

async fn cert_it(project: &str, b: &mut SslConnectorBuilder, cert: &str) -> Result<()> {
    if !Path::new(cert).is_file() {
        let auth = Authenticator::auth().await?;
        let secret_manager = SecretManager::new_with_authenticator(auth).await;

        let secret = secret_manager
            .get_secret(project, cert.replace(".crt", "").as_str())
            .await?;

        write(cert, &secret[..]).await?;
    }
    b.set_ca_file(cert)?;
    Ok(())
}

// returns the connection string as a secret
pub async fn get_cxn_secret(project: &str, db: &str) -> Result<String> {
    let auth = Authenticator::auth().await?;
    let secret_manager = SecretManager::new_with_authenticator(auth).await;

    let secret = secret_manager
        .get_secret(project, format!("db-cxn-{db}").as_str())
        .await?;

    Ok(String::from_utf8(secret)?)
}

async fn set_cxn_secret(project: &str, db: &str, cxn: &str) -> Result<()> {
    let auth = Authenticator::auth().await?;
    let sec_mgr = SecretManager::new_with_authenticator(auth).await;

    sec_mgr
        .create_secret(project, format!("db-cxn-{db}").as_str(), cxn)
        .await?;

    Ok(())
}

// async fn get_google_token(a: &str) -> Result<String> {
//     let gurl = format!("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience={a}");

//     let req = Request::builder()
//         .method(Method::GET)
//         .uri(gurl)
//         .header("Metadata-Flavor", "Google")
//         .body(Body::empty())?;

//     let client = Client::new();
//     let res = client.request(req).await?;

//     let body = &body::to_bytes(res.into_body()).await?;

//     Ok(std::str::from_utf8(body)?.to_string())
//     // Ok("somerandomtoken".to_string())
// }

pub struct Db {
    // sa: ServiceAccountKey,
    xai: PgPool,
    orgpg: Arc<RwLock<HashMap<String, PgPool>>>,
    redis: RedisPool,
    project: String,
    migrator: Option<String>,
}

impl Db {
    pub async fn new(project: &str) -> Result<Self> {
        let isdev = if let Ok(x_env) = env::var("X_ENV")
            && x_env == "prod"
        {
            false
        } else {
            true
        };

        let (xai, redis) = try_join!(
            Self::connect_xai_pg(project, isdev),
            Self::connect_redis(project, isdev)
        )?;

        // create client connection for sentry gRPC here and get session from there
        // and return Ok((true, Session))
        Ok(Self {
            xai,
            orgpg: Arc::new(RwLock::new(HashMap::new())),
            redis,
            project: project.to_owned(),
            migrator: None,
        })
    }

    pub async fn new_with_migrator(project: &str, migrator: &str) -> Result<Self> {
        // let sa = read_service_account_key(&secret_path).await?;
        let isdev = if let Ok(x_env) = env::var("X_ENV")
            && x_env == "prod"
        {
            false
        } else {
            true
        };

        let (xai, redis) = try_join!(
            Self::connect_xai_pg(project, isdev),
            Self::connect_redis(project, isdev)
        )?;

        // create client connection for sentry gRPC here and get session from there
        // and return Ok((true, Session))
        Ok(Self {
            xai,
            orgpg: Arc::new(RwLock::new(HashMap::new())),
            redis,
            project: project.to_owned(),
            migrator: Some(migrator.to_owned()),
        })
    }

    async fn connect_xai_pg(project: &str, isdev: bool) -> Result<PgPool> {
        let db = if isdev { "dev-xai" } else { "xai" };
        connect_pg(
            project,
            get_pg_conf(project, db).await?,
            4,
            true,
            &get_zone_cert(),
        )
        .await
    }

    pub async fn get_xai_pg(&self) -> Result<Object> {
        if let Ok(p) = self.xai.get().await {
            Ok(p)
        } else {
            Err(anyhow!("failed to get xai.pg"))
        }
    }

    pub async fn connect_redis(
        project: &str,
        // sa: &ServiceAccountKey,
        isdev: bool,
    ) -> Result<RedisPool> {
        let cfg = get_redis_conf(project, isdev).await?;

        let pool = cfg.create_pool(Some(Runtime::Tokio1))?;

        Ok(pool)
    }

    pub async fn ensure_tenant_db(&self, org: &str) -> Result<()> {
        {
            let p = self.orgpg.read().await;
            if p.contains_key(org) {
                return Ok(());
            }
        }

        let p = Self::connect_tenant_pg(&self.project, org).await?;
        let mut l = self.orgpg.write().await;
        l.insert(org.to_owned(), p);

        Ok(())
    }

    async fn connect_tenant_pg(project: &str, org: &str) -> Result<PgPool> {
        let pool = connect_pg(
            project,
            get_pg_conf(project, org.replace("o-", "db").to_lowercase().as_str()).await?,
            2,
            true,
            &get_zone_cert(),
        )
        .await?;

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
            if let Some(d) = o.get(org)
                && let Ok(p) = d.get().await
            {
                p
            } else {
                return Err(anyhow!("while getting tenant db[{}]", org));
            }
        };
        Ok(db)
    }

    pub async fn get_redis(redis: &RedisPool) -> Result<Connection> {
        Ok(redis.get().await?)
    }

    // This is a complicated step, which createa and migrates a new tenant
    // The following steps are involved:
    // 0. Get db-cxn-<cluster>-default from secrets
    // 1. Create a DB user in a particular cluster - depending on the cluster
    // 2. log in and create a new database
    // 3. Grant all privilleges of the newly created DB to the newly created user
    // 4. Now, for this database create the connection string and update `secret manager`
    // 5. Call migration script to run migration on this database
    // 6. Ensure tenant
    pub async fn new_tenant_db(&self, org: &str, cluster: &str) -> Result<()> {
        let (conf, cxn) = self.get_cluster_default(&self.project, cluster).await?;

        let (usr, pwd) = self.create_db_user(&cxn, org).await?;
        let db = self.create_database(&cxn, org, &usr).await?;

        let port = conf.get_ports()[0];
        let host = match &conf.get_hosts()[0] {
            tokio_postgres::config::Host::Tcp(s) => s,
            tokio_postgres::config::Host::Unix(s) => {
                let s = s.to_str();
                if let Some(s) = &s {
                    s.to_owned()
                } else {
                    return Err(anyhow!("host not found"));
                }
            }
        };

        let opt = if let Some(opt) = conf.get_options() {
            opt.replace('=', "%3D")
        } else {
            "".to_owned()
        };

        let cxnstr: String = format!(
            "postgresql://{usr}:{pwd}@{host}:{port}/{db}?sslmode=verify-full&options={opt}"
        );
        set_cxn_secret(&self.project, &db, &cxnstr).await?;

        // check if connection is working properly or not
        let _ = self.get_tenant_pg(org).await?;
        self.run_migration(org).await?;

        Ok(())
    }

    async fn get_cluster_default(&self, project: &str, cluster: &str) -> Result<(PgConf, PgPool)> {
        let auth = Authenticator::auth().await?;
        let secret = SecretManager::new_with_authenticator(auth)
            .await
            .get_secret(
                project,
                format!("projects/{project}/secrets/db-cxn-{cluster}-default/versions/latest")
                    .as_str(),
            )
            .await?;

        let cxn = String::from_utf8(secret)?;

        let conf = PgConf::from_str(cxn.replace("verify-full", "require").as_str())?;

        Ok((
            conf.clone(),
            connect_pg(project, conf, 4, true, "roach.crt").await?,
        ))
    }

    async fn create_db_user(&self, pg: &PgPool, org: &str) -> Result<(String, String)> {
        let ext = generate_password(4).await?;
        let usr = format!("{}_{ext}", org.replace("o-", "adm1n_").to_lowercase());
        let pwd = generate_password(22).await?;

        let pg = pg.get().await?;
        let qry = format!("CREATE USER {usr} WITH PASSWORD '{pwd}'");

        let stmt = pg.prepare(&qry).await?;

        pg.execute(&stmt, &[]).await?;

        Ok((usr, pwd))
    }

    async fn create_database(&self, pg: &PgPool, org: &str, owner: &str) -> Result<String> {
        let db = org.replace("o-", "db").to_lowercase();

        let pg = pg.get().await?;
        let qry = format!("CREATE DATABASE {db} OWNER {owner}");

        let stmt = pg.prepare(&qry).await?;

        pg.execute(&stmt, &[]).await?;

        Ok(db)
    }

    pub async fn get_cache_pool_arced(&self) -> Arc<RedisPool> {
        Arc::new(self.redis.clone())
    }

    async fn cmd_get(conn: &mut Connection, key: &str) -> Result<Vec<u8>> {
        match cmd("GET").arg(key).query_async(conn).await {
            Ok(d) => Ok(d),
            Err(e) => Err(anyhow!(e)),
        }
    }

    pub async fn get_cache(&self, key: &str) -> Result<Vec<u8>> {
        let mut conn = match Self::get_redis(&self.redis).await {
            Ok(c) => c,
            Err(e) => {
                return Err(anyhow!(e));
            }
        };

        Self::cmd_get(&mut conn, key).await
    }

    pub async fn get_cache_for_pool(cache: Arc<RedisPool>, key: &str) -> Result<Vec<u8>> {
        let mut conn = match Self::get_redis(&cache).await {
            Ok(c) => c,
            Err(e) => return Err(anyhow!(e)),
        };

        Self::cmd_get(&mut conn, key).await
    }

    async fn cmd_set(conn: &mut Connection, key: &str, val: &[u8], ttl: Option<u16>) -> Result<()> {
        let mut command = cmd("SET");

        command.arg(key).arg(val);
        if let Some(t) = ttl {
            command.arg("EX").arg(t);
        }

        command.query_async(conn).await?;

        Ok(())
    }

    // sets a key to cache with ttl
    pub async fn set_cache(&self, key: &str, val: &[u8], ttl: Option<u16>) -> Result<()> {
        let mut conn = match Self::get_redis(&self.redis).await {
            Ok(c) => c,
            Err(e) => {
                return Err(anyhow!(e));
            }
        };

        Self::cmd_set(&mut conn, key, val, ttl).await
    }

    pub async fn set_cache_for_pool(
        cache: Arc<RedisPool>,
        key: &str,
        val: &[u8],
        ttl: Option<u16>,
    ) -> Result<()> {
        let mut conn = match Self::get_redis(&cache).await {
            Ok(c) => c,
            Err(e) => return Err(anyhow!(e)),
        };

        Self::cmd_set(&mut conn, key, val, ttl).await
    }

    // deletes from cache
    pub async fn del_cache(&self, key: &str) -> Result<usize> {
        let mut conn = match Self::get_redis(&self.redis).await {
            Ok(c) => c,
            Err(e) => {
                return Err(anyhow!(e));
            }
        };

        match cmd("DEL").arg(key).query_async(&mut conn).await {
            Ok(d) => Ok(d),
            Err(e) => Err(anyhow!(e)),
        }
    }
}

#[derive(Serialize)]
struct RunMigration {
    id: String,
}

impl Db {
    async fn run_migration(&self, org: &str) -> Result<()> {
        // let rb = RunMigration { id: org.to_owned() };
        // let body = serde_json::to_vec(&rb)?;

        // let mig = if let Some(m) = &self.migrator {
        //     m.to_owned()
        // } else {
        //     return Err(anyhow!("Migrator not initialized"));
        // };

        // let token = if !mig.contains("localhost") {
        //     get_google_token(&mig).await?
        // } else {
        //     String::new()
        // };

        // let uri = format!("{}/m", &mig);

        // let req = Request::builder()
        //     .method(Method::POST)
        //     .header(AUTHORIZATION, format!("Bearer {token}"))
        //     .uri(&uri)
        //     .body(Body::from(body))?;

        // let res = if !&mig.contains("localhost") {
        //     let client = Client::builder().build(
        //         hyper_rustls::HttpsConnectorBuilder::new()
        //             .with_native_roots()
        //             .https_or_http()
        //             .enable_http1()
        //             .enable_http2()
        //             .build(),
        //     );

        //     client.request(req).await?
        // } else {
        //     let client = Client::builder().build(HttpConnector::new());

        //     client.request(req).await?
        // };

        // if res.status() != StatusCode::OK {
        //     return Err(anyhow!(
        //         "non-200 response code {} from migrator",
        //         res.status()
        //     ));
        // }
        unimplemented!("Run migration for Org: [{org}]")
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        for p in glob::glob("*.crt").unwrap().filter_map(Result::ok) {
            if let Err(e) = remove_file(&p) {
                println!("Error trying to delete file {}: {e:?}", p.display());
            }
        }
    }
}

fn get_zone_cert() -> String {
    if let Ok(e) = env::var("X_ENV")
        && e == "prod"
    {
        "roach.crt".to_string()
    } else {
        "dev-roach.crt".to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use anyhow::Result;
    // use google_secretmanager1::oauth2::read_service_account_key;

    use crate::Db;

    use super::set_cxn_secret;

    #[tokio::test]
    async fn new_tenant_db() -> Result<()> {
        let proj = env::var("X_PROJECT")?;
        // let sa_path = env::var("SERVICE_ACCOUNT")?;

        let db = Db::new_with_migrator(proj.as_str(), "http://localhost:8080").await?;

        let neworg = env::var("X_ORG")?;
        let cluster = env::var("X_CLUSTER")?;
        db.new_tenant_db(&neworg, &cluster).await?;

        Ok(())
    }

    #[tokio::test]
    async fn create_secret() -> Result<()> {
        let proj = env::var("X_PROJECT")?;

        set_cxn_secret(&proj, "s0m3database", "S0m3S3cr3tMess@g3")
            .await
            .unwrap();

        Ok(())
    }

    #[tokio::test]
    async fn connect_xai() -> Result<()> {
        let proj = env::var("X_PROJECT")?;

        let db = Db::new(proj.as_str()).await?;

        let _ = db.get_xai_pg().await?;

        Ok(())
    }

    #[tokio::test]
    async fn del_cache() -> Result<()> {
        let proj = env::var("X_PROJECT")?;

        let db = Db::new(proj.as_str()).await?;

        let t = db.del_cache("hello").await?;
        println!("DelCache: {t}");

        Ok(())
    }

    #[tokio::test]
    async fn get_cache() -> Result<()> {
        let proj = env::var("X_PROJECT")?;

        let db = Db::new(proj.as_str()).await?;

        let t = db.get_cache("hello").await?;
        println!("GetCache: {}", String::from_utf8(t).unwrap());

        Ok(())
    }
}
