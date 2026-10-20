use crate::hashing::tip5::Tip5Error;
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};
use ibig::UBig;
use pokenoun::codec::{is_null, pair, Decode, Encode, Error};
use pokenoun::{Arena, Noun};

/// Z-Set: A deterministic self-balancing binary search tree (treap) for sets
/// Based on the Hoon z-set implementation from nockchain
///
/// This is a treap that uses hash-based priorities for balancing:
/// - Ordering: gor-tip (single hash comparison)
/// - Balancing: mor-tip (double hash comparison)
/// - Fallback: dor-tip (structural comparison)
use core::cmp::Ordering;
use core::fmt::Debug;

/// A z-set is a self-balancing binary search tree for sets
#[derive(Clone)]
pub struct ZSet<T> {
    root: Option<Box<Node<T>>>,
}

/// Internal node structure
#[derive(Clone)]
struct Node<T> {
    value: T,
    left: Option<Box<Node<T>>>,
    right: Option<Box<Node<T>>>,
}

impl<T> Node<T> {
    fn new(value: T) -> Self {
        Node {
            value,
            left: None,
            right: None,
        }
    }
}

/// Trait for types that can be compared using dor-tip (structural ordering)
pub trait DorTip {
    fn dor_tip(&self, other: &Self) -> Ordering;
}

/// Default implementation for types that implement Ord
impl<T: Ord> DorTip for T {
    fn dor_tip(&self, other: &Self) -> Ordering {
        self.cmp(other)
    }
}

impl<T> ZSet<T>
where
    T: Encode + DorTip + Clone + Debug + PartialEq,
{
    /// Create a new empty z-set
    pub fn new() -> Self {
        ZSet { root: None }
    }

    /// Insert a value, maintaining treap invariants.
    ///
    /// Panics if the value's noun cannot be TIP5-hashed. Use [`Self::try_put`]
    /// to handle that.
    pub fn put(&mut self, value: T) {
        self.try_put(value)
            .unwrap_or_else(|e| panic!("z-set value could not be tip5-hashed: {}", e));
    }

    /// Fallible insertion; see [`Self::put`].
    pub fn try_put(&mut self, value: T) -> Result<(), Tip5Error> {
        Self::compute_tip5_hash(&value)?;
        let root = Self::put_recursive(self.root.clone(), value)?;
        self.root = root;
        Ok(())
    }

    /// Insert a value with debug output
    #[cfg(feature = "std")]
    pub fn put_with_debug(&mut self, value: T)
    where
        T: Debug,
    {
        println!("Inserting value: {:?}", value);
        self.root = Self::put_recursive_debug(self.root.take(), value, 0);
    }

    /// Public debug structure method
    pub fn debug_structure(&self) -> String
    where
        T: Debug,
    {
        match &self.root {
            None => "  (empty)".to_string(),
            Some(node) => Self::debug_node_structure_internal(node, 1),
        }
    }

    /// Internal debug structure method (always available, not just in tests)
    fn debug_structure_internal(&self) -> String {
        match &self.root {
            None => "  (empty)".to_string(),
            Some(node) => Self::debug_node_structure_internal(node, 1),
        }
    }

    fn debug_node_structure_internal(node: &Box<Node<T>>, indent: usize) -> String {
        let spaces = "  ".repeat(indent);
        let value_str = format!("{:?}", node.value);
        let mut result = format!("{}Node({})\n", spaces, value_str);

        match &node.left {
            None => result.push_str(&format!("{}  L: null\n", spaces)),
            Some(left) => {
                result.push_str(&format!("{}  L:\n", spaces));
                result.push_str(&Self::debug_node_structure_internal(left, indent + 2));
            }
        }

        match &node.right {
            None => result.push_str(&format!("{}  R: null", spaces)),
            Some(right) => {
                result.push_str(&format!("{}  R:\n", spaces));
                result.push_str(&Self::debug_node_structure_internal(right, indent + 2));
            }
        }

        result
    }

    /// Recursive insertion with debug output
    #[cfg(feature = "std")]
    fn put_recursive_debug(
        node: Option<Box<Node<T>>>,
        value: T,
        depth: usize,
    ) -> Option<Box<Node<T>>>
    where
        T: Debug,
    {
        let indent = "  ".repeat(depth);

        match node {
            None => {
                println!("{}Creating new node for {:?}", indent, value);
                Some(Box::new(Node::new(value)))
            }
            Some(mut n) => {
                let cmp =
                    Self::gor_tip(&value, &n.value).expect("z-set value could not be tip5-hashed");
                println!(
                    "{}Comparing {:?} with node {:?}: {:?}",
                    indent, value, n.value, cmp
                );

                match cmp {
                    Ordering::Equal => {
                        println!("{}Value already exists, no-op", indent);
                        Some(n)
                    }
                    Ordering::Less => {
                        println!("{}Going left", indent);
                        n.left = Self::put_recursive_debug(n.left, value, depth + 1);

                        if let Some(left_child) = &n.left {
                            let mor_cmp = Self::mor_tip(&n.value, &left_child.value)
                                .expect("z-set value could not be tip5-hashed");
                            println!(
                                "{}mor_tip({:?}, {:?}) = {:?}",
                                indent, n.value, left_child.value, mor_cmp
                            );
                            if mor_cmp != Ordering::Less {
                                println!("{}Rotating right", indent);
                                Some(Self::rotate_right(n))
                            } else {
                                println!("{}No rotation needed", indent);
                                Some(n)
                            }
                        } else {
                            Some(n)
                        }
                    }
                    Ordering::Greater => {
                        println!("{}Going right", indent);
                        n.right = Self::put_recursive_debug(n.right, value, depth + 1);

                        if let Some(right_child) = &n.right {
                            let mor_cmp = Self::mor_tip(&n.value, &right_child.value)
                                .expect("z-set value could not be tip5-hashed");
                            println!(
                                "{}mor_tip({:?}, {:?}) = {:?}",
                                indent, n.value, right_child.value, mor_cmp
                            );
                            if mor_cmp != Ordering::Less {
                                println!("{}Rotating left", indent);
                                Some(Self::rotate_left(n))
                            } else {
                                println!("{}No rotation needed", indent);
                                Some(n)
                            }
                        } else {
                            Some(n)
                        }
                    }
                }
            }
        }
    }

    /// Recursive insertion with rotations
    fn put_recursive(
        node: Option<Box<Node<T>>>,
        value: T,
    ) -> Result<Option<Box<Node<T>>>, Tip5Error> {
        match node {
            None => {
                // Empty node, create new
                Ok(Some(Box::new(Node::new(value))))
            }
            Some(mut n) => {
                let cmp = Self::gor_tip(&value, &n.value)?;

                match cmp {
                    Ordering::Equal => {
                        // Value exists, no-op for set
                        Ok(Some(n))
                    }
                    Ordering::Less => {
                        // Insert left
                        n.left = Self::put_recursive(n.left, value)?;

                        // Check if rotation needed (mor-tip comparison)
                        // In Hoon: if (mor-tip n.a n.c) is true, NO rotation
                        // mor-tip returns Less when first has higher priority (smaller mor value)
                        if let Some(left_child) = &n.left {
                            if Self::mor_tip(&n.value, &left_child.value)? != Ordering::Less {
                                // Parent does NOT have higher priority, rotate right
                                Ok(Some(Self::rotate_right(n)))
                            } else {
                                Ok(Some(n))
                            }
                        } else {
                            Ok(Some(n))
                        }
                    }
                    Ordering::Greater => {
                        // Insert right
                        n.right = Self::put_recursive(n.right, value)?;

                        // Check if rotation needed (mor-tip comparison)
                        // In Hoon: if (mor-tip n.a n.c) is true, NO rotation
                        // mor-tip returns Less when first has higher priority (smaller mor value)
                        if let Some(right_child) = &n.right {
                            if Self::mor_tip(&n.value, &right_child.value)? != Ordering::Less {
                                // Parent does NOT have higher priority, rotate left
                                Ok(Some(Self::rotate_left(n)))
                            } else {
                                Ok(Some(n))
                            }
                        } else {
                            Ok(Some(n))
                        }
                    }
                }
            }
        }
    }

    /// Right rotation
    fn rotate_right(mut n: Box<Node<T>>) -> Box<Node<T>> {
        let mut left = n
            .left
            .take()
            .expect("rotate_right called with no left child");
        n.left = left.right.take();
        left.right = Some(n);
        left
    }

    /// Left rotation
    fn rotate_left(mut n: Box<Node<T>>) -> Box<Node<T>> {
        let mut right = n
            .right
            .take()
            .expect("rotate_left called with no right child");
        n.right = right.left.take();
        right.left = Some(n);
        right
    }

    /// Check if a value exists.
    ///
    /// Panics if the value's noun cannot be TIP5-hashed. Use [`Self::try_has`]
    /// to handle that.
    pub fn has(&self, value: &T) -> bool {
        self.try_has(value)
            .unwrap_or_else(|e| panic!("z-set value could not be tip5-hashed: {}", e))
    }

    /// Fallible membership check; see [`Self::has`].
    pub fn try_has(&self, value: &T) -> Result<bool, Tip5Error> {
        Self::has_recursive(&self.root, value)
    }

    fn has_recursive(node: &Option<Box<Node<T>>>, value: &T) -> Result<bool, Tip5Error> {
        match node {
            None => Ok(false),
            Some(n) => match Self::gor_tip(value, &n.value)? {
                Ordering::Equal => Ok(true),
                Ordering::Less => Self::has_recursive(&n.left, value),
                Ordering::Greater => Self::has_recursive(&n.right, value),
            },
        }
    }

    /// Delete a value from the tree.
    ///
    /// Panics if the value's noun cannot be TIP5-hashed. Use [`Self::try_del`]
    /// to handle that.
    pub fn del(&mut self, value: &T) {
        self.try_del(value)
            .unwrap_or_else(|e| panic!("z-set value could not be tip5-hashed: {}", e));
    }

    /// Fallible deletion; see [`Self::del`].
    pub fn try_del(&mut self, value: &T) -> Result<(), Tip5Error> {
        self.root = Self::del_recursive(self.root.take(), value)?;
        Ok(())
    }

    fn del_recursive(
        node: Option<Box<Node<T>>>,
        value: &T,
    ) -> Result<Option<Box<Node<T>>>, Tip5Error> {
        match node {
            None => Ok(None),
            Some(mut n) => {
                match Self::gor_tip(value, &n.value)? {
                    Ordering::Equal => {
                        // Found node to delete, merge children
                        Self::merge_children(n.left, n.right)
                    }
                    Ordering::Less => {
                        n.left = Self::del_recursive(n.left, value)?;
                        Ok(Some(n))
                    }
                    Ordering::Greater => {
                        n.right = Self::del_recursive(n.right, value)?;
                        Ok(Some(n))
                    }
                }
            }
        }
    }

    /// Merge two subtrees maintaining heap property
    fn merge_children(
        left: Option<Box<Node<T>>>,
        right: Option<Box<Node<T>>>,
    ) -> Result<Option<Box<Node<T>>>, Tip5Error> {
        match (left, right) {
            (None, None) => Ok(None),
            (Some(l), None) => Ok(Some(l)),
            (None, Some(r)) => Ok(Some(r)),
            (Some(mut l), Some(mut r)) => {
                // Choose root based on mor-tip priority
                if Self::mor_tip(&l.value, &r.value)? == Ordering::Less {
                    // l has higher priority (smaller mor-tip), make it root
                    l.right = Self::merge_children(l.right, Some(r))?;
                    Ok(Some(l))
                } else {
                    // r has higher priority, make it root
                    r.left = Self::merge_children(Some(l), r.left)?;
                    Ok(Some(r))
                }
            }
        }
    }

    /// Collect all values in order
    pub fn tap(&self) -> Vec<T> {
        let mut result = Vec::new();
        Self::tap_recursive(&self.root, &mut result);
        result
    }

    fn tap_recursive(node: &Option<Box<Node<T>>>, result: &mut Vec<T>) {
        if let Some(n) = node {
            Self::tap_recursive(&n.right, result);
            result.push(n.value.clone());
            Self::tap_recursive(&n.left, result);
        }
    }

    /// Get the number of elements
    pub fn wyt(&self) -> usize {
        Self::wyt_recursive(&self.root)
    }

    fn wyt_recursive(node: &Option<Box<Node<T>>>) -> usize {
        match node {
            None => 0,
            Some(n) => 1 + Self::wyt_recursive(&n.left) + Self::wyt_recursive(&n.right),
        }
    }

    /// Check if the set is empty
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// Get the number of elements (alias for wyt)
    pub fn len(&self) -> usize {
        self.wyt()
    }

    /// Create an iterator over the values
    pub fn iter(&self) -> ZSetIter<'_, T> {
        let mut stack = Vec::new();
        if let Some(ref root) = self.root {
            Self::push_left(&mut stack, root);
        }
        ZSetIter { stack }
    }

    #[cfg(test)]
    fn debug_node_structure(node: &Box<Node<T>>, indent: usize) -> String {
        let spaces = "  ".repeat(indent);
        let value_str = format!("{:?}", node.value);
        let left_str = match &node.left {
            None => format!("{}  L: null", spaces),
            Some(left) => format!(
                "{}  L:\n{}",
                spaces,
                Self::debug_node_structure(left, indent + 2)
            ),
        };
        let right_str = match &node.right {
            None => format!("{}  R: null", spaces),
            Some(right) => format!(
                "{}  R:\n{}",
                spaces,
                Self::debug_node_structure(right, indent + 2)
            ),
        };
        format!("{}Node({})\n{}\n{}", spaces, value_str, left_str, right_str)
    }

    /// Helper for iterator: push all left nodes onto stack
    fn push_left<'a>(stack: &mut Vec<&'a Box<Node<T>>>, mut node: &'a Box<Node<T>>) {
        loop {
            stack.push(node);
            match node.left {
                Some(ref left) => node = left,
                None => break,
            }
        }
    }

    /// Compute TIP5 hash of a value and convert to UBig integer
    fn compute_tip5_hash(value: &T) -> Result<UBig, Tip5Error> {
        let bytes = value
            .to_jam()
            .map_err(|error| Tip5Error::SerializationError(error.to_string()))?;
        let hash = crate::hashing::hasher::hash_noun_varlen(&bytes)?;
        Ok(hash.to_ubig())
    }

    /// gor-tip: Compare by single hash (UBig integer), fallback to dor-tip
    fn gor_tip(a: &T, b: &T) -> Result<Ordering, Tip5Error> {
        let hash_a = Self::compute_tip5_hash(a)?;
        let hash_b = Self::compute_tip5_hash(b)?;

        // Compare the UBig integers - ORIGINAL (not reversed)
        Ok(match hash_a.cmp(&hash_b) {
            // Note: a compared to b (original)
            Ordering::Equal => a.dor_tip(b),
            other => other,
        })
    }

    /// mor-tip: Compare by double hash (hash of hash concatenated with itself), fallback to dor-tip
    fn mor_tip(a: &T, b: &T) -> Result<Ordering, Tip5Error> {
        // Compute double-tip for each value
        let double_a = Self::compute_double_tip5_hash(a)?;
        let double_b = Self::compute_double_tip5_hash(b)?;

        // ORIGINAL (not reversed)
        Ok(match double_a.cmp(&double_b) {
            // Note: a compared to b (original)
            Ordering::Equal => a.dor_tip(b),
            other => other,
        })
    }

    /// Compute double-tip: hash(hash(value) ++ hash(value))
    fn compute_double_tip5_hash(value: &T) -> Result<UBig, Tip5Error> {
        let bytes = value
            .to_jam()
            .map_err(|error| Tip5Error::SerializationError(error.to_string()))?;
        let hash = crate::hashing::hasher::hash_noun_varlen(&bytes)?;
        Ok(crate::hashing::hash_ten_cell(hash.clone(), hash).to_ubig())
    }

    /// Build from an iterator (gas equivalent)
    pub fn gas<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = T>,
    {
        let mut set = Self::new();
        for v in iter {
            set.put(v);
        }
        set
    }

    /// Convert the z-set to a Hashable structure
    /// This preserves the exact tree structure for hashing
    pub fn to_hashable<F>(&self, val_fn: F) -> crate::hashing::hashable::Hashable
    where
        F: Fn(&T) -> crate::hashing::hashable::Hashable + Copy,
    {
        use crate::hashing::hashable::Hashable;

        match &self.root {
            None => Hashable::null(), // Empty tree
            Some(node) => Self::node_to_hashable(node, val_fn),
        }
    }

    /// Fallible variant of [`Self::to_hashable`] for values whose hashable
    /// construction can fail (for example note-data with unbased atoms).
    pub fn try_to_hashable<F, E>(&self, val_fn: F) -> Result<crate::hashing::hashable::Hashable, E>
    where
        F: Fn(&T) -> Result<crate::hashing::hashable::Hashable, E> + Copy,
    {
        use crate::hashing::hashable::Hashable;

        match &self.root {
            None => Ok(Hashable::null()),
            Some(node) => Self::try_node_to_hashable(node, val_fn),
        }
    }

    fn try_node_to_hashable<F, E>(
        node: &Box<Node<T>>,
        val_fn: F,
    ) -> Result<crate::hashing::hashable::Hashable, E>
    where
        F: Fn(&T) -> Result<crate::hashing::hashable::Hashable, E> + Copy,
    {
        use crate::hashing::hashable::Hashable;

        let node_hashable = val_fn(&node.value)?;

        let left = match &node.left {
            None => Hashable::null(),
            Some(left_node) => Self::try_node_to_hashable(left_node, val_fn)?,
        };

        let right = match &node.right {
            None => Hashable::null(),
            Some(right_node) => Self::try_node_to_hashable(right_node, val_fn)?,
        };

        Ok(Hashable::triple(node_hashable, left, right))
    }

    /// Convert a node to hashable recursively
    fn node_to_hashable<F>(node: &Box<Node<T>>, val_fn: F) -> crate::hashing::hashable::Hashable
    where
        F: Fn(&T) -> crate::hashing::hashable::Hashable + Copy,
    {
        use crate::hashing::hashable::Hashable;

        // Get hashable for the current node's value
        let node_hashable = val_fn(&node.value);

        // Process left subtree
        let left = match &node.left {
            None => Hashable::null(),
            Some(left_node) => Self::node_to_hashable(left_node, val_fn),
        };

        // Process right subtree
        let right = match &node.right {
            None => Hashable::null(),
            Some(right_node) => Self::node_to_hashable(right_node, val_fn),
        };

        // Return as triple: [node_value, left, right]
        // This matches the Hoon z-set hashable structure
        Hashable::triple(node_hashable, left, right)
    }
}

/// Iterator over ZSet values
pub struct ZSetIter<'a, T> {
    stack: Vec<&'a Box<Node<T>>>,
}

impl<'a, T> Iterator for ZSetIter<'a, T>
where
    T: Encode + DorTip + Clone + Debug + PartialEq,
{
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(node) = self.stack.pop() {
            // If this node has a right child, push all its left descendants
            if let Some(ref right) = node.right {
                ZSet::push_left(&mut self.stack, right);
            }
            Some(&node.value)
        } else {
            None
        }
    }
}

// Implement Default
impl<T> Default for ZSet<T>
where
    T: Encode + DorTip + Clone + Debug + PartialEq,
{
    fn default() -> Self {
        Self::new()
    }
}

// Debug implementation for visualization
impl<T: Debug> Debug for ZSet<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ZSet {{ root: ")?;
        fmt_node(&self.root, f, 0)?;
        write!(f, " }}")
    }
}

// Implement PartialEq for ZSet
impl<T> PartialEq for ZSet<T>
where
    T: Encode + DorTip + Clone + Debug + PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        // Two sets are equal if they contain the same elements
        self.tap() == other.tap()
    }
}

// Implement Eq for ZSet
impl<T> Eq for ZSet<T> where T: Encode + DorTip + Clone + Debug + PartialEq + Eq {}

// Implement Hash for ZSet
use core::hash::{Hash, Hasher};

impl<T> Hash for ZSet<T>
where
    T: Encode + DorTip + Clone + Debug + PartialEq + Hash,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash the elements in order
        let items = self.tap();
        items.hash(state);
    }
}

// Implement PartialOrd for ZSet
impl<T> PartialOrd for ZSet<T>
where
    T: Encode + DorTip + Clone + Debug + PartialEq + PartialOrd,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.tap().partial_cmp(&other.tap())
    }
}

// Implement Ord for ZSet
impl<T> Ord for ZSet<T>
where
    T: Encode + DorTip + Clone + Debug + PartialEq + Eq + Ord,
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.tap().cmp(&other.tap())
    }
}

// Helper function for debug formatting
fn fmt_node<T: Debug>(
    node: &Option<Box<Node<T>>>,
    f: &mut core::fmt::Formatter<'_>,
    depth: usize,
) -> core::fmt::Result {
    match node {
        None => write!(f, "~"),
        Some(n) => {
            write!(f, "\n{:indent$}[{:?}]", "", n.value, indent = depth * 2)?;
            if n.left.is_some() || n.right.is_some() {
                write!(f, "\n{:indent$}  L: ", "", indent = depth * 2)?;
                fmt_node(&n.left, f, depth + 2)?;
                write!(f, "\n{:indent$}  R: ", "", indent = depth * 2)?;
                fmt_node(&n.right, f, depth + 2)?;
            }
            Ok(())
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use noun_serde::NounEncode;

    // Wrapper for i32 to implement NounEncode
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct TestInt(i32);

    impl NounEncode for TestInt {
        fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
            use nockvm::noun::Atom;
            // Convert to u64 for atom creation (handle negative values)
            let value = if self.0 < 0 {
                // For negative numbers, use two's complement representation
                (self.0 as i64) as u64
            } else {
                self.0 as u64
            };
            Atom::new(alloc, value).as_noun()
        }
    }
    impl pokenoun::codec::Encode for TestInt {
        fn encode(
            &self,
            arena: &mut pokenoun::Arena,
        ) -> Result<pokenoun::Noun, pokenoun::codec::Error> {
            (self.0 as i64 as u64).encode(arena)
        }
    }

    #[test]
    fn test_basic_operations() {
        let mut set: ZSet<TestInt> = ZSet::new();

        // Test insertion
        set.put(TestInt(5));
        set.put(TestInt(3));
        set.put(TestInt(7));
        set.put(TestInt(1));
        set.put(TestInt(9));
        set.put(TestInt(5)); // Duplicate, should be ignored

        // Test has
        assert!(set.has(&TestInt(5)));
        assert!(set.has(&TestInt(3)));
        assert!(!set.has(&TestInt(10)));

        // Test wyt (count)
        assert_eq!(set.wyt(), 5);

        // Test deletion
        set.del(&TestInt(3));
        assert!(!set.has(&TestInt(3)));
        assert_eq!(set.wyt(), 4);

        // Test tap (in-order traversal)
        // Note: ZSet uses hash-based ordering (gor-tip), not natural ordering
        let items = set.tap();
        assert_eq!(items.len(), 4);
        // Verify all expected values are present
        let values: Vec<i32> = items.iter().map(|t| t.0).collect();
        assert!(values.contains(&1));
        assert!(values.contains(&5));
        assert!(values.contains(&7));
        assert!(values.contains(&9));
    }

    #[test]
    fn test_gas_construction() {
        let values = vec![
            TestInt(10),
            TestInt(20),
            TestInt(15),
            TestInt(5),
            TestInt(25),
            TestInt(20), // Duplicate
        ];

        let set = ZSet::gas(values);

        assert_eq!(set.wyt(), 5); // Only 5 unique values
        assert!(set.has(&TestInt(15)));

        // Check all items are present
        let items = set.tap();
        assert_eq!(items.len(), 5);
        let values: Vec<i32> = items.iter().map(|t| t.0).collect();
        assert!(values.contains(&5));
        assert!(values.contains(&10));
        assert!(values.contains(&15));
        assert!(values.contains(&20));
        assert!(values.contains(&25));
    }

    #[test]
    fn test_iterator() {
        let mut set = ZSet::new();
        for i in [5, 2, 8, 1, 9, 3] {
            set.put(TestInt(i));
        }

        let collected: Vec<_> = set.iter().map(|t| t.0).collect();
        assert_eq!(collected.len(), 6);

        // All values should be present
        for i in [1, 2, 3, 5, 8, 9] {
            assert!(collected.contains(&i));
        }
    }

    #[test]
    fn test_numbers_1_to_10_tree_structure() {
        use crate::hashing::tip5::Tip5Hasher;
        use nockapp::noun::slab::NounSlab;
        use noun_serde::NounEncode;

        println!("\n=== Testing ZSet with numbers 1 through 10 ===\n");

        let mut set = ZSet::new();

        // Insert numbers 1 through 10
        for i in 1..=10 {
            println!("Inserting {}", i);
            set.put(TestInt(i));
        }

        // Get the tree structure
        println!("\n--- Tree Structure ---");
        println!("{}", set.debug_structure());

        // Get the in-order traversal
        let items = set.tap();
        println!("\n--- In-order Traversal (based on gor-tip ordering) ---");
        for (idx, item) in items.iter().enumerate() {
            // Compute the hash for each value to understand ordering
            use nockvm::noun::NounAllocator;

            let mut slab: NounSlab = NounSlab::new();
            let noun = item.to_noun(&mut slab);
            let space = slab.noun_space();
            let hash = Tip5Hasher::hash_noun_varlen(noun, &space).unwrap();
            println!("{}: value={}, hash={:x?}", idx, item.0, &hash.values[0..2]);
            // Show first 2 values of hash
        }

        // Verify all numbers are present
        println!("\n--- Verification ---");
        assert_eq!(set.wyt(), 10, "Should have exactly 10 elements");
        for i in 1..=10 {
            assert!(set.has(&TestInt(i)), "Should contain {}", i);
        }
        println!("✓ All numbers 1-10 are present in the set");

        // Show the actual order
        let ordered_values: Vec<i32> = items.iter().map(|t| t.0).collect();
        println!("\n--- Final Order ---");
        println!("Order: {:?}", ordered_values);
    }
}

impl<T: Encode> Encode for ZSet<T> {
    fn encode(&self, arena: &mut Arena) -> Result<Noun, Error> {
        fn tree<T: Encode>(node: &Option<Box<Node<T>>>, arena: &mut Arena) -> Result<Noun, Error> {
            let Some(node) = node else {
                return Ok(arena.atom0());
            };
            let value = node.value.encode(arena)?;
            let left = tree(&node.left, arena)?;
            let right = tree(&node.right, arena)?;
            let children = arena.alloc_cell(left, right);
            Ok(arena.alloc_cell(value, children))
        }
        tree(&self.root, arena)
    }
}

impl<T> Decode for ZSet<T>
where
    T: Decode + Encode + DorTip + Clone + Debug + PartialEq,
{
    fn decode(noun: Noun, arena: &Arena) -> Result<Self, Error> {
        fn tree<T: Decode>(noun: Noun, arena: &Arena) -> Result<Option<Box<Node<T>>>, Error> {
            if is_null(noun, arena) {
                return Ok(None);
            }
            let (value, children) = pair(noun, arena)?;
            let (left, right) = pair(children, arena)?;
            Ok(Some(Box::new(Node {
                value: T::decode(value, arena)?,
                left: tree(left, arena)?,
                right: tree(right, arena)?,
            })))
        }
        Ok(Self {
            root: tree(noun, arena)?,
        })
    }
}

#[cfg(feature = "std")]
impl<T: Encode> noun_serde::NounEncode for ZSet<T> {
    fn to_noun<A: nockvm::noun::NounAllocator>(&self, alloc: &mut A) -> nockvm::noun::Noun {
        crate::noun_codec::encode_runtime(self, alloc)
    }
}

#[cfg(feature = "std")]
impl<T> noun_serde::NounDecode for ZSet<T>
where
    T: Decode + Encode + DorTip + Clone + Debug + PartialEq,
{
    fn from_noun(
        noun: &nockvm::noun::Noun,
        space: &nockvm::noun::NounSpace,
    ) -> Result<Self, noun_serde::NounDecodeError> {
        crate::noun_codec::decode_runtime(*noun, space)
    }
}
