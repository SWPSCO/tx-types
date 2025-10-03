use nockvm::interpreter::{Error, Mote};
use nockvm::jets::JetErr;
use nockvm::jets::JetErr::*;
use nockvm::noun::D;

use crate::form::FieldError;

pub fn jet_err<T>() -> Result<T, JetErr> {
    Err(Fail(Error::Deterministic(Mote::Exit, D(0))))
}

pub fn field_error_to_jet_err(e: FieldError) -> JetErr {
    match e {
        FieldError::OrderedRootError => Fail(Error::Deterministic(Mote::Exit, D(0))),
    }
}
