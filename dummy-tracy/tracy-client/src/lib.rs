// Dummy tracy-client to prevent compilation issues

pub struct Client;

impl Client {
    pub fn start() -> Self {
        Client
    }
    
    pub fn running() -> bool {
        false
    }
}

pub fn span(_name: &str) -> Span {
    Span
}

pub struct Span;

impl Drop for Span {
    fn drop(&mut self) {}
}

pub fn frame_mark() {}

pub fn message(_msg: &str, _callstack_depth: usize) {}

pub fn set_thread_name(_name: &str) {}