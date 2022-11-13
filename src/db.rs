use std::{collections::HashMap, fs::remove_file, path::Path, str::FromStr, sync::Arc};

use anyhow::{anyhow, Result};
use deadpool_postgres::{Manager, ManagerConfig, Object, Pool as PgPool, RecyclingMethod};
use deadpool_redis::{Config as RConf, Connection, Pool as RedisPool, Runtime};
use google_secretmanager1::{
    api::{AddSecretVersionRequest, Automatic, Replication, Secret, SecretPayload},
    hyper::{
        body, client::HttpConnector, header::AUTHORIZATION, Body, Client, Method, Request,
        StatusCode,
    },
    hyper_rustls::{self, HttpsConnector},
    oauth2::{ServiceAccountAuthenticator, ServiceAccountKey},
    SecretManager,
};
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

pub async fn get_pg_conf(
    project: &str,
    sa: &ServiceAccountKey,
    db: &str,
) -> Result<tokio_postgres::Config> {
    let cxn = get_cxn_secret(project, sa, db).await?;
    Ok(PgConf::from_str(
        cxn.replace("verify-full", "require").as_str(),
    )?)
}

pub async fn get_redis_conf(
    project: &str,
    sa: &ServiceAccountKey,
) -> Result<deadpool_redis::Config> {
    let cxn = get_cxn_secret(project, sa, "cache").await?;
    Ok(RConf::from_url(cxn))
}

pub async fn connect_pg(
    sa: &ServiceAccountKey,
    project: &str,
    cfg: tokio_postgres::Config,
    pool_size: usize,
    isroach: bool,
    cert: &str,
) -> Result<PgPool> {
    let mgr_config = ManagerConfig {
        recycling_method: RecyclingMethod::Fast,
    };

    let mgr = if isroach {
        let mut builder = SslConnector::builder(SslMethod::tls())?;
        cert_it(sa, project, &mut builder, cert).await?;

        let connector = MakeTlsConnector::new(builder.build());
        Manager::from_config(cfg, connector, mgr_config)
        // let mut builder = Tls::builder(::tls()).expect("unable to create sslconnector builder");
    } else {
        Manager::from_config(cfg, NoTls, mgr_config)
    };
    let pool = PgPool::builder(mgr).max_size(pool_size).build()?;

    Ok(pool)
}

async fn cert_it(
    secret: &ServiceAccountKey,
    project: &str,
    b: &mut SslConnectorBuilder,
    cert: &str,
) -> Result<()> {
    if !Path::new(cert).is_file() {
        let hub = secrets_hub(secret).await?;

        let secret_name = format!(
            "projects/{project}/secrets/{}/versions/latest",
            cert.replace(".crt", "")
        );
        let (_, s) = hub
            .projects()
            .secrets_versions_access(&secret_name)
            .doit()
            .await?;

        let secret = if let Some(pl) = s.payload && let Some(d) = pl.data {
            base64::decode(d.as_bytes())?
        } else {
            return Err(anyhow!("Invalid db credentials"));
        };

        write(cert, &secret[..]).await?;
    }
    b.set_ca_file(cert)?;
    Ok(())
}

// returns the connection string as a secret
pub async fn get_cxn_secret(project: &str, secret: &ServiceAccountKey, db: &str) -> Result<String> {
    let hub = secrets_hub(secret).await?;

    let secret_name = format!("projects/{project}/secrets/db-cxn-{db}/versions/latest");
    let (_, s) = hub
        .projects()
        .secrets_versions_access(&secret_name)
        .doit()
        .await?;

    let secret = if let Some(pl) = s.payload && let Some(d) = pl.data {
        base64::decode(d.as_bytes())?
    } else {
        return Err(anyhow!("Invalid db credentials"));
    };

    Ok(String::from_utf8(secret)?)
}

async fn set_cxn_secret(
    project: &str,
    secret: &ServiceAccountKey,
    db: &str,
    cxn: &str,
) -> Result<()> {
    let hub = secrets_hub(secret).await?;

    let secret_id = format!("db-cxn-{db}");
    let parent = format!("projects/{project}");

    hub.projects()
        .secrets_create(
            Secret {
                replication: Some(Replication {
                    automatic: Some(Automatic::default()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            &parent,
        )
        .secret_id(&secret_id)
        .doit()
        .await?;

    let data = base64::encode(cxn.as_bytes());

    let vrq = AddSecretVersionRequest {
        payload: Some(SecretPayload {
            data: Some(data),
            ..Default::default()
        }),
    };
    let parent = format!("projects/{project}/secrets/{secret_id}");
    hub.projects()
        .secrets_add_version(vrq, &parent)
        .doit()
        .await?;

    Ok(())
}

async fn secrets_hub(
    secret: &ServiceAccountKey,
) -> Result<SecretManager<HttpsConnector<HttpConnector>>> {
    let auth = ServiceAccountAuthenticator::builder(secret.clone())
        .build()
        .await?;
    let hub = SecretManager::new(
        Client::builder().build(
            hyper_rustls::HttpsConnectorBuilder::new()
                .with_native_roots()
                .https_or_http()
                .enable_http1()
                .enable_http2()
                .build(),
        ),
        auth,
    );

    Ok(hub)
}

async fn get_google_token(a: &str) -> Result<String> {
    let gurl = format!("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience={a}");

    let req = Request::builder()
        .method(Method::GET)
        .uri(gurl)
        .header("Metadata-Flavor", "Google")
        .body(Body::empty())?;

    let client = Client::new();
    let res = client.request(req).await?;

    let body = &body::to_bytes(res.into_body()).await?;

    Ok(std::str::from_utf8(body)?.to_string())
    // Ok("somerandomtoken".to_string())
}

pub struct Db {
    sa: ServiceAccountKey,
    xai: PgPool,
    orgpg: Arc<RwLock<HashMap<String, PgPool>>>,
    redis: RedisPool,
    project: String,
    migrator: String,
}

impl Db {
    pub async fn new(project: &str, sa: ServiceAccountKey, migrator: &str) -> Result<Self> {
        // let gcs = GClient::default();
        // let c = get_db_conf(&gcs, "xai.db").await?;
        let (xai, redis) = try_join!(
            Self::connect_xai_pg(project, &sa),
            Self::connect_redis(project, &sa)
        )?;

        // create client connection for sentry gRPC here and get session from there
        // and return Ok((true, Session))
        Ok(Self {
            sa,
            xai,
            orgpg: Arc::new(RwLock::new(HashMap::new())),
            redis,
            project: project.to_owned(),
            migrator: migrator.to_owned(),
        })
    }

    async fn connect_xai_pg(project: &str, sa: &ServiceAccountKey) -> Result<PgPool> {
        connect_pg(
            sa,
            project,
            get_pg_conf(project, sa, "xai").await?,
            4,
            true,
            "roach.crt",
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

    async fn connect_redis(project: &str, sa: &ServiceAccountKey) -> Result<RedisPool> {
        // let cfg = RConf::from_url(format!("redis://:{}@{}:{}", pwd, host, port));
        let cfg = get_redis_conf(project, sa).await?;

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

        let p = Self::connect_tenant_pg(&self.project, &self.sa, org).await?;
        let mut l = self.orgpg.write().await;
        l.insert(org.to_owned(), p);

        Ok(())
    }

    async fn connect_tenant_pg(project: &str, sa: &ServiceAccountKey, org: &str) -> Result<PgPool> {
        let pool = connect_pg(
            sa,
            project,
            get_pg_conf(project, sa, org.replace("o-", "db").to_lowercase().as_str()).await?,
            2,
            true,
            "roach.crt",
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
        let (conf, cxn) = self
            .get_cluster_default(&self.sa, &self.project, cluster)
            .await?;

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
        set_cxn_secret(&self.project, &self.sa, &db, &cxnstr).await?;

        // check if connection is working properly or not
        let _ = self.get_tenant_pg(org).await?;
        self.run_migration(org).await?;

        Ok(())
    }

    async fn get_cluster_default(
        &self,
        secret: &ServiceAccountKey,
        project: &str,
        cluster: &str,
    ) -> Result<(PgConf, PgPool)> {
        let hub = secrets_hub(secret).await?;

        let secret_name =
            format!("projects/{project}/secrets/db-cxn-{cluster}-default/versions/latest");
        let (_, s) = hub
            .projects()
            .secrets_versions_access(&secret_name)
            .doit()
            .await?;

        let cxn = if let Some(pl) = s.payload && let Some(d) = pl.data {
            String::from_utf8(base64::decode(d.as_bytes())?)?
        } else {
            return Err(anyhow!("Invalid db credentials"));
        };

        let conf = PgConf::from_str(cxn.replace("verify-full", "require").as_str())?;

        Ok((
            conf.clone(),
            connect_pg(secret, project, conf, 4, true, "roach.crt").await?,
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
}

#[derive(Serialize)]
struct RunMigration {
    id: String,
}

impl Db {
    async fn run_migration(&self, org: &str) -> Result<()> {
        let rb = RunMigration { id: org.to_owned() };
        let body = serde_json::to_vec(&rb)?;

        let token = if !self.migrator.contains("localhost") {
            get_google_token(&self.migrator).await?
        } else {
            String::new()
        };

        let uri = format!("{}/m", &self.migrator);

        let req = Request::builder()
            .method(Method::POST)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .uri(&uri)
            .body(Body::from(body))?;

        let res = if !self.migrator.contains("localhost") {
            let client = Client::builder().build(
                hyper_rustls::HttpsConnectorBuilder::new()
                    .with_native_roots()
                    .https_or_http()
                    .enable_http1()
                    .enable_http2()
                    .build(),
            );

            client.request(req).await?
        } else {
            let client = Client::builder().build(HttpConnector::new());

            client.request(req).await?
        };

        if res.status() != StatusCode::OK {
            return Err(anyhow!(
                "non-200 response code {} from migrator",
                res.status()
            ));
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use std::env;

    use anyhow::Result;
    use google_secretmanager1::oauth2::ServiceAccountKey;
    use tokio::fs::read_to_string;

    use crate::Db;

    use super::set_cxn_secret;

    async fn get_service_account() -> Result<ServiceAccountKey> {
        let f = if let Ok(s) = env::var("SERVICE_ACCOUNT_JSON") {
            s
        } else {
            let safile = env::var("SERVICE_ACCOUNT")?;
            read_to_string(&safile).await?
        };

        Ok(serde_json::from_str::<ServiceAccountKey>(&f)?)
    }

    #[tokio::test]
    async fn new_tenant_db() -> Result<()> {
        let proj = env::var("X_PROJECT")?;
        let db = Db::new(
            proj.as_str(),
            get_service_account().await?,
            "http://localhost:8080",
        )
        .await?;

        let neworg = env::var("X_ORG")?;
        let cluster = env::var("X_CLUSTER")?;
        db.new_tenant_db(&neworg, &cluster).await?;

        Ok(())
    }

    #[tokio::test]
    async fn create_secret() -> Result<()> {
        let proj = env::var("X_PROJECT")?;

        let sa = get_service_account().await?;
        set_cxn_secret(&proj, &sa, "s0m3database", "S0m3S3cr3tMess@g3")
            .await
            .unwrap();

        Ok(())
    }
}
