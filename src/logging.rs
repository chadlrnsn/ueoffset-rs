use env_logger;
use log;

pub fn init_logger() {
  env_logger::builder()
  .filter_level(log::LevelFilter::Info)
  .init();
} 

