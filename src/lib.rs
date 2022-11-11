#![feature(let_chains)]

mod db;

pub use db::{connect_pg, get_pg_conf, Db};
