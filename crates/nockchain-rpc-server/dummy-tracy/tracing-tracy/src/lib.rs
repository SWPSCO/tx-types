// Dummy tracing-tracy to prevent compilation issues

use tracing_core::{span, Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

pub use tracy_client::{Client, Span};

pub struct TracyLayer;

impl TracyLayer {
    pub fn new() -> Self {
        TracyLayer
    }
}

impl Default for TracyLayer {
    fn default() -> Self {
        TracyLayer
    }
}

impl<S> Layer<S> for TracyLayer
where
    S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_event(&self, _event: &Event<'_>, _ctx: Context<'_, S>) {}
    
    fn on_enter(&self, _id: &span::Id, _ctx: Context<'_, S>) {}
    
    fn on_exit(&self, _id: &span::Id, _ctx: Context<'_, S>) {}
    
    fn on_close(&self, _id: span::Id, _ctx: Context<'_, S>) {}
}

pub fn set_thread_name(_name: &str) {}