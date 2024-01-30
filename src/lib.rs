#![feature(let_chains)]

#[macro_use]
extern crate log;

mod db;

pub use db::{connect_pg, get_pg_conf, Db};
pub use deadpool_redis::Pool as RedisPool;
