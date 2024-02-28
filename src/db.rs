use std::{collections::HashMap, env, fs::remove_file, path::Path, str::FromStr, sync::Arc};

use anyhow::{anyhow, Result};
use aws_config::{load_defaults, BehaviorVersion};
use deadpool_postgres::{Manager, ManagerConfig, Object, Pool as PgPool};
use deadpool_redis::{redis::cmd, Config as RConf, Connection, Pool as RedisPool, Runtime};

use openssl::ssl::{SslConnector, SslConnectorBuilder, SslMethod};
use passwords::PasswordGenerator;
use postgres_openssl::MakeTlsConnector;
use serde::Serialize;
use tokio::{
    fs::write,
    sync::{OnceCell, RwLock},
    try_join,
};
use tokio_postgres::{Config as PgConf, NoTls};

static CERT_DIR: OnceCell<tempdir::TempDir> = OnceCell::const_new();

async fn create_cert_dir() -> tempdir::TempDir {
    tempdir::TempDir::new("x-db").unwrap()
}

async fn cert_dir() -> &'static Path {
    CERT_DIR.get_or_init(create_cert_dir).await.path()
}

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

pub async fn get_pg_conf(db: &str) -> Result<tokio_postgres::Config> {
    let cxn = match get_cxn_secret(db).await {
        Ok(cxn) => cxn,
        Err(e) => {
            error!("get_pg_conf: error trying to get connection secret: {e:?}");
            return Err(anyhow!(e));
        }
    };

    Ok(PgConf::from_str(
        cxn.replace("verify-full", "require").as_str(),
    )?)
}

pub async fn get_redis_conf(isdev: bool) -> Result<deadpool_redis::Config> {
    let secretname = if isdev { "dev-cache" } else { "cache" };
    let cxn = match get_cxn_secret(secretname).await {
        Ok(cxn) => cxn,
        Err(e) => {
            error!("Db.get_redis_conf: error trying to get redis connection secret: {e:?}");
            return Err(anyhow!(e));
        }
    };

    Ok(RConf::from_url(cxn))
}

pub async fn connect_pg(
    cfg: tokio_postgres::Config,
    pool_size: usize,
    isroach: bool,
    cert: &str,
) -> Result<PgPool> {
    let mgr_cfg = ManagerConfig::default();

    let mgr = if isroach {
        let mut builder = SslConnector::builder(SslMethod::tls())?;
        cert_it(&mut builder, cert).await?;

        let connector = MakeTlsConnector::new(builder.build());
        Manager::from_config(cfg, connector, mgr_cfg)
        // let mut builder = Tls::builder(::tls()).expect("unable to create sslconnector builder");
    } else {
        Manager::from_config(cfg, NoTls, mgr_cfg)
    };
    let pool = PgPool::builder(mgr).max_size(pool_size).build()?;

    Ok(pool)
}

async fn cert_it(b: &mut SslConnectorBuilder, cert: &str) -> Result<()> {
    let crtpth = cert_dir().await.join(cert);
    if !crtpth.is_file() {
        let cfg = load_defaults(BehaviorVersion::latest()).await;
        let secret_manager = aws_sdk_secretsmanager::Client::new(&cfg);

        let secret = match secret_manager
            .get_secret_value()
            .secret_id(cert.replace(".crt", "").as_str())
            .send()
            .await
        {
            Ok(res) => {
                if let Some(s) = res.secret_string() {
                    s.to_string()
                } else {
                    error!("Db.cert_it: no cert: [{cert}]");
                    return Err(anyhow!("no cert"));
                }
            }
            Err(e) => {
                error!("cert_it: error trying to get roach data: [{cert}]: {e:?}");
                return Err(anyhow!("no certificate for [{cert}]"));
            }
        };

        write(&crtpth, secret).await?;
    }
    info!("gets roach cert!");

    b.set_ca_file(&crtpth)?;
    Ok(())
}

// returns the connection string as a secret
pub async fn get_cxn_secret(db: &str) -> Result<String> {
    // let auth = Authenticator::auth().await?;
    let cfg = load_defaults(BehaviorVersion::latest()).await;
    // let cfg = aws_config::defaults(BehaviorVersion::latest()).region("ap-south-1").load().await;
    let secret_manager = aws_sdk_secretsmanager::Client::new(&cfg);

    let secret_name = format!("db-cxn-{db}");
    let secret = match secret_manager
        .get_secret_value()
        .secret_id(&secret_name)
        .send()
        .await
    {
        Ok(s) => {
            if let Some(secret) = s.secret_string {
                secret
            } else {
                error!("Db.get_cxn_secret: no secret for db[{secret_name}]");
                return Err(anyhow!("no secret for db"));
            }
        }
        Err(e) => {
            error!("Db.get_cxn_secret: error trying to get connection secret for db[{secret_name}]: {e:?}");
            return Err(anyhow!(e));
        }
    };

    Ok(secret)
}

async fn set_cxn_secret(db: &str, cxn: &str) -> Result<()> {
    let cfg = load_defaults(BehaviorVersion::latest()).await;
    let client = aws_sdk_secretsmanager::Client::new(&cfg);

    let secret_name = format!("db-cxn-{db}");
    client
        .create_secret()
        .name(&secret_name)
        .secret_string(cxn)
        .send()
        .await?;

    Ok(())
}

// async fn get_google_token(a: &str) -> Result<String> {
//     // let gurl = format!("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience={a}");

//     // let req = Request::builder()
//     //     .method(Method::GET)
//     //     .uri(gurl)
//     //     .header("Metadata-Flavor", "Google")
//     //     .body(Body::empty())?;

//     // let client = Client::new();
//     // let res = client.request(req).await?;

//     // let body = &body::to_bytes(res.into_body()).await?;

//     // Ok(std::str::from_utf8(body)?.to_string())
//     // Ok("somerandomtoken".to_string())
// }

pub struct Db {
    dev: bool,
    host: PgPool,
    orgpg: Arc<RwLock<HashMap<String, PgPool>>>,
    redis: RedisPool,
    migrator: Option<String>,
}

impl Db {
    pub async fn new() -> Result<Self> {
        let dev = if let Ok(x_env) = env::var("X_ENV")
            && x_env == "prod"
        {
            false
        } else {
            true
        };

        info!("Db.new: initializing DB for dev[{dev}]");

        let (host, redis) = match try_join!(Self::connect_host_pg(dev), Self::connect_redis(dev)) {
            Ok(d) => d,
            Err(e) => {
                error!("Db.new: error intializing: {e:?}");
                return Err(anyhow!(e));
            }
        };

        // create client connection for sentry gRPC here and get session from there
        // and return Ok((true, Session))
        Ok(Self {
            dev,
            host,
            orgpg: Arc::new(RwLock::new(HashMap::new())),
            redis,
            migrator: None,
        })
    }

    pub async fn new_with_migrator(migrator: &str) -> Result<Self> {
        // let sa = read_service_account_key(&secret_path).await?;
        let dev = if let Ok(x_env) = env::var("X_ENV")
            && x_env == "prod"
        {
            false
        } else {
            true
        };

        let (host, redis) = try_join!(Self::connect_host_pg(dev), Self::connect_redis(dev))?;

        // create client connection for sentry gRPC here and get session from there
        // and return Ok((true, Session))
        Ok(Self {
            dev,
            host,
            orgpg: Arc::new(RwLock::new(HashMap::new())),
            redis,
            migrator: Some(migrator.to_owned()),
        })
    }

    async fn connect_host_pg(isdev: bool) -> Result<PgPool> {
        let db = if isdev { "dev-host" } else { "host" };
        let cfg = match get_pg_conf(db).await {
            Ok(cfg) => cfg,
            Err(e) => {
                error!("Db.connect_xai_pg: error getting pg conf: {e:?}");
                return Err(anyhow!(e));
            }
        };
        connect_pg(cfg, 4, true, &get_zone_cert()).await
    }

    pub async fn host_pg(&self) -> Result<Object> {
        if let Ok(p) = self.host.get().await {
            Ok(p)
        } else {
            Err(anyhow!("failed to get xai.pg"))
        }
    }

    pub async fn connect_redis(
        // sa: &ServiceAccountKey,
        isdev: bool,
    ) -> Result<RedisPool> {
        let cfg = match get_redis_conf(isdev).await {
            Ok(cfg) => cfg,
            Err(e) => {
                error!("Db.connect_redis: error getting redis config: {e:?}");
                return Err(anyhow!(e));
            }
        };

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

        let p = Self::connect_tenant_pg(org, self.dev).await?;
        let mut l = self.orgpg.write().await;
        l.insert(org.to_owned(), p);

        Ok(())
    }

    async fn connect_tenant_pg(org: &str, dev: bool) -> Result<PgPool> {
        let pool = connect_pg(
            get_pg_conf(
                org.replace("o-", if dev { "devdb" } else { "db" })
                    .to_lowercase()
                    .as_str(),
            )
            .await?,
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

    pub async fn tenant_pg(&self, org: &str) -> Result<Object> {
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
        let (conf, cxn) = self.get_cluster_default(cluster).await?;

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
        set_cxn_secret(&db, &cxnstr).await?;

        // check if connection is working properly or not
        let _ = self.tenant_pg(org).await?;
        self.run_migration(org).await?;

        Ok(())
    }

    async fn get_cluster_default(&self, cluster: &str) -> Result<(PgConf, PgPool)> {
        let cfg = load_defaults(BehaviorVersion::latest()).await;
        let secret = aws_sdk_secretsmanager::Client::new(&cfg)
            .get_secret_value()
            .secret_id(cluster)
            .send()
            .await?;

        let cxn = if let Some(secret) = secret.secret_string() {
            secret
        } else {
            error!("get_cluster_default: no such secret: [{cluster}]");
            return Err(anyhow!("no such secret for cluster"));
        };

        let conf = PgConf::from_str(cxn.replace("verify-full", "require").as_str())?;

        Ok((conf.clone(), connect_pg(conf, 4, true, "roach.crt").await?))
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
        warn!(
            "run_migration: for org[{org}] is not implemented yet for migrator[{:?}]",
            self.migrator
        );
        // let rb = RunMigration { id: org.to_owned() };
        // let body = serde_json::to_vec(&rb)?;

        // let mig = if let Some(m) = &self.migrator {
        //     m.to_owned()
        // } else {
        //     return Err(anyhow!("Migrator not initialized"));
        // };

        // let token = if !mig.contains("localhost") {
        //     // get_google_token(&mig).await?
        //     todo!("run_migration")
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
                error!("Error trying to delete file {}: {e:?}", p.display());
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
        // let sa_path = env::var("SERVICE_CCOUNT")?;

        let db = Db::new_with_migrator("http://localhost:8080").await?;

        let neworg = env::var("X_ORG")?;
        let cluster = env::var("X_CLUSTER")?;
        db.new_tenant_db(&neworg, &cluster).await?;

        Ok(())
    }

    #[tokio::test]
    async fn create_secret() -> Result<()> {
        set_cxn_secret("s0m3database", "S0m3S3cr3tMess@g3")
            .await
            .unwrap();

        Ok(())
    }

    #[tokio::test]
    async fn connect_host() -> Result<()> {
        pretty_env_logger::init();
        let db = Db::new().await?;

        let _ = db.host_pg().await?;

        Ok(())
    }

    #[tokio::test]
    async fn connect_tenant_pg() -> Result<()> {
        let db = Db::new().await?;

        let _ = db.tenant_pg("o-01GFZBQ275D9C56014S28TQT1V").await?;

        Ok(())
    }

    #[tokio::test]
    async fn del_cache() -> Result<()> {
        let db = Db::new().await?;

        let t = db.del_cache("hello").await?;
        println!("DelCache: {t}");

        Ok(())
    }

    #[tokio::test]
    async fn get_cache() -> Result<()> {
        let db = Db::new().await?;

        let t = db.get_cache("hello").await?;
        println!("GetCache: {}", String::from_utf8(t).unwrap());

        Ok(())
    }
}
