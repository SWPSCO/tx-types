use nockvm::interpreter::Context;
use nockvm::jets::list::util::flop;
use nockvm::jets::util::slot;
use nockvm::jets::JetErr;
use nockvm::mem::NockStack;
use nockvm::noun::{Noun, D, T};

use crate::utils::vec_to_hoon_list;

pub fn leaf_sequence_jet(context: &mut Context, subject: Noun) -> Result<Noun, JetErr> {
    let t = slot(subject, 6)?;
    leaf_sequence(&mut context.stack, t)
}

pub fn leaf_sequence(stack: &mut NockStack, t: Noun) -> Result<Noun, JetErr> {
    let mut leaf: Vec<u64> = Vec::<u64>::new();
    do_leaf_sequence(t, &mut leaf)?;
    Ok(vec_to_hoon_list(stack, &leaf))
}

pub fn do_leaf_sequence(noun: Noun, vec: &mut Vec<u64>) -> Result<(), JetErr> {
    if noun.is_atom() {
        vec.push(noun.as_atom()?.as_u64()?);
        Ok(())
    } else {
        let cell = noun.as_cell()?;
        do_leaf_sequence(cell.head(), vec)?;
        do_leaf_sequence(cell.tail(), vec)?;
        Ok(())
    }
}

pub fn dyck_jet(context: &mut Context, subject: Noun) -> Result<Noun, JetErr> {
    let stack = &mut context.stack;
    let t = slot(subject, 6)?;
    dyck(stack, t)
}

pub fn dyck(stack: &mut NockStack, t: Noun) -> Result<Noun, JetErr> {
    let vec = dyck_recursive(stack, t, D(0))?;
    flop(stack, vec)
}

fn dyck_recursive(stack: &mut NockStack, t: Noun, vec: Noun) -> Result<Noun, JetErr> {
    if t.is_atom() {
        Ok(vec)
    } else {
        let t_cell = t.as_cell()?;
        let vec_inner = T(stack, &[D(0), vec]);
        let dyck_inner = dyck_recursive(stack, t_cell.head(), vec_inner)?;
        let vec_outer = T(stack, &[D(1), dyck_inner]);
        dyck_recursive(stack, t_cell.tail(), vec_outer)
    }
}

#[cfg(test)]
mod tests {
    use nockvm::jets::util::test::*;
    use nockvm::noun::{D, T};

    use super::*;

    #[test]
    fn test_mont_reduction_jet() {
        let c = &mut init_context();

        // > (leaf-sequence:shape.zeke 1)
        // ~[1]
        let sam = D(1);
        let res = T(&mut c.stack, &[D(1), D(0)]);
        assert_jet(c, leaf_sequence_jet, sam, res);

        // > (leaf-sequence:shape.zeke ~)
        // ~[0]
        let sam = D(0);
        let res = T(&mut c.stack, &[D(0), D(0)]);
        assert_jet(c, leaf_sequence_jet, sam, res);

        // > (leaf-sequence:shape.zeke ~[1 2 3])
        // ~[1 2 3 0]
        let sam = T(&mut c.stack, &[D(1), D(2), D(3), D(0)]);
        let res = T(&mut c.stack, &[D(1), D(2), D(3), D(0), D(0)]);
        assert_jet(c, leaf_sequence_jet, sam, res);

        // > (leaf-sequence:shape.zeke [[1 2] 3])
        // ~[1 2 3]
        let t12 = T(&mut c.stack, &[D(1), D(2)]);
        let sam = T(&mut c.stack, &[t12, D(3), D(0)]);
        let res = T(&mut c.stack, &[D(1), D(2), D(3), D(0), D(0)]);
        assert_jet(c, leaf_sequence_jet, sam, res);

        // > (leaf-sequence:shape.zeke [[1 2] 3 [4 5] 6])
        // ~[1 2 3 4 5 6]
        let t12 = T(&mut c.stack, &[D(1), D(2)]);
        let t45 = T(&mut c.stack, &[D(4), D(5)]);
        let sam = T(&mut c.stack, &[t12, D(3), t45, D(6)]);
        let res = T(&mut c.stack, &[D(1), D(2), D(3), D(4), D(5), D(6), D(0)]);
        assert_jet(c, leaf_sequence_jet, sam, res);
    }
}
