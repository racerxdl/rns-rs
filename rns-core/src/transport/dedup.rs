use alloc::vec;
use alloc::vec::Vec;

/// Bounded FIFO packet-hash deduplication.
///
/// Retains at most `max_size` unique packet hashes. New unique hashes are
/// appended in insertion order; when full, the oldest retained hash is evicted.
/// Re-inserting a retained hash is a no-op and does not refresh its recency.
pub struct PacketHashlist {
    queue: PacketHashQueue,
    set: PacketHashSet,
}

impl PacketHashlist {
    pub fn new(max_size: usize) -> Self {
        Self {
            queue: PacketHashQueue::new(max_size),
            set: PacketHashSet::new(max_size),
        }
    }

    /// Check if a hash is currently retained.
    pub fn is_duplicate(&self, hash: &[u8; 32]) -> bool {
        self.set.contains(hash)
    }

    /// Retain a hash. If the dedup table is full, evict the oldest unique hash.
    pub fn add(&mut self, hash: [u8; 32]) {
        if self.queue.capacity() == 0 || self.set.contains(&hash) {
            return;
        }

        if self.queue.len() == self.queue.capacity() {
            let evicted = self
                .queue
                .pop_front()
                .expect("full dedup queue must have an oldest entry to evict");
            let removed = self.set.remove(&evicted);
            debug_assert!(removed, "evicted hash must exist in dedup set");
        }

        let inserted = self.set.insert(hash);
        debug_assert!(inserted, "new hash must insert into dedup set");
        self.queue.push_back(hash);
    }

    /// Total number of retained packet hashes.
    pub fn len(&self) -> usize {
        debug_assert_eq!(self.queue.len(), self.set.len());
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

struct PacketHashQueue {
    entries: Vec<[u8; 32]>,
    head: usize,
    len: usize,
}

impl PacketHashQueue {
    fn new(capacity: usize) -> Self {
        Self {
            entries: vec![[0u8; 32]; capacity],
            head: 0,
            len: 0,
        }
    }

    fn capacity(&self) -> usize {
        self.entries.len()
    }

    fn len(&self) -> usize {
        self.len
    }

    fn push_back(&mut self, hash: [u8; 32]) {
        debug_assert!(self.len < self.capacity());
        if self.capacity() == 0 {
            return;
        }
        let tail = (self.head + self.len) % self.capacity();
        self.entries[tail] = hash;
        self.len += 1;
    }

    fn pop_front(&mut self) -> Option<[u8; 32]> {
        if self.len == 0 || self.capacity() == 0 {
            return None;
        }
        let hash = self.entries[self.head];
        self.head = (self.head + 1) % self.capacity();
        self.len -= 1;
        if self.len == 0 {
            self.head = 0;
        }
        Some(hash)
    }
}

struct PacketHashSet {
    buckets: Vec<Option<[u8; 32]>>,
    len: usize,
}

impl PacketHashSet {
    fn new(max_entries: usize) -> Self {
        Self {
            buckets: vec![None; bucket_capacity(max_entries)],
            len: 0,
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn contains(&self, hash: &[u8; 32]) -> bool {
        if self.buckets.is_empty() {
            return false;
        }

        let mut idx = self.bucket_index(hash);
        loop {
            match self.buckets[idx] {
                Some(entry) if &entry == hash => return true,
                Some(_) => idx = (idx + 1) & (self.buckets.len() - 1),
                None => return false,
            }
        }
    }

    fn insert(&mut self, hash: [u8; 32]) -> bool {
        if self.buckets.is_empty() {
            return false;
        }

        let mut idx = self.bucket_index(&hash);
        loop {
            match self.buckets[idx] {
                Some(entry) if entry == hash => return false,
                Some(_) => idx = (idx + 1) & (self.buckets.len() - 1),
                None => {
                    self.buckets[idx] = Some(hash);
                    self.len += 1;
                    return true;
                }
            }
        }
    }

    fn remove(&mut self, hash: &[u8; 32]) -> bool {
        if self.buckets.is_empty() {
            return false;
        }

        let mut idx = self.bucket_index(hash);
        loop {
            match self.buckets[idx] {
                Some(entry) if &entry == hash => break,
                Some(_) => idx = (idx + 1) & (self.buckets.len() - 1),
                None => return false,
            }
        }

        self.buckets[idx] = None;
        self.len -= 1;

        let mut next = (idx + 1) & (self.buckets.len() - 1);
        while let Some(entry) = self.buckets[next].take() {
            self.len -= 1;
            let inserted = self.insert(entry);
            debug_assert!(inserted, "cluster reinsert after removal must succeed");
            next = (next + 1) & (self.buckets.len() - 1);
        }

        true
    }

    fn bucket_index(&self, hash: &[u8; 32]) -> usize {
        debug_assert!(!self.buckets.is_empty());
        (hash_bytes(hash) as usize) & (self.buckets.len() - 1)
    }
}

fn bucket_capacity(max_entries: usize) -> usize {
    if max_entries == 0 {
        return 0;
    }

    let min_capacity = max_entries.saturating_mul(2).max(1);
    min_capacity.next_power_of_two()
}

fn hash_bytes(hash: &[u8; 32]) -> u64 {
    let mut state = 0xcbf29ce484222325u64;
    for byte in hash {
        state ^= u64::from(*byte);
        state = state.wrapping_mul(0x100000001b3);
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(seed: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = seed;
        h
    }

    #[test]
    fn test_new_hash_not_duplicate() {
        let hl = PacketHashlist::new(100);
        assert!(!hl.is_duplicate(&make_hash(1)));
    }

    #[test]
    fn test_added_hash_is_duplicate() {
        let mut hl = PacketHashlist::new(100);
        let h = make_hash(1);
        hl.add(h);
        assert!(hl.is_duplicate(&h));
    }

    #[test]
    fn test_duplicate_insert_does_not_increase_len() {
        let mut hl = PacketHashlist::new(2);
        let h = make_hash(1);

        hl.add(h);
        hl.add(h);

        assert_eq!(hl.len(), 1);
        assert!(hl.is_duplicate(&h));
    }

    #[test]
    fn test_full_hashlist_evicts_oldest_unique_hash() {
        let mut hl = PacketHashlist::new(3);
        let h1 = make_hash(1);
        let h2 = make_hash(2);
        let h3 = make_hash(3);
        let h4 = make_hash(4);

        hl.add(h1);
        hl.add(h2);
        hl.add(h3);
        hl.add(h4);

        assert!(!hl.is_duplicate(&h1));
        assert!(hl.is_duplicate(&h2));
        assert!(hl.is_duplicate(&h3));
        assert!(hl.is_duplicate(&h4));
        assert_eq!(hl.len(), 3);
    }

    #[test]
    fn test_duplicate_does_not_refresh_recency() {
        let mut hl = PacketHashlist::new(2);
        let h1 = make_hash(1);
        let h2 = make_hash(2);
        let h3 = make_hash(3);

        hl.add(h1);
        hl.add(h2);
        hl.add(h2);
        hl.add(h3);

        assert!(!hl.is_duplicate(&h1));
        assert!(hl.is_duplicate(&h2));
        assert!(hl.is_duplicate(&h3));
        assert_eq!(hl.len(), 2);
    }

    #[test]
    fn test_fifo_eviction_order_is_exact_across_multiple_inserts() {
        let mut hl = PacketHashlist::new(3);
        let h1 = make_hash(1);
        let h2 = make_hash(2);
        let h3 = make_hash(3);
        let h4 = make_hash(4);
        let h5 = make_hash(5);

        hl.add(h1);
        hl.add(h2);
        hl.add(h3);
        hl.add(h4);
        hl.add(h5);

        assert!(!hl.is_duplicate(&h1));
        assert!(!hl.is_duplicate(&h2));
        assert!(hl.is_duplicate(&h3));
        assert!(hl.is_duplicate(&h4));
        assert!(hl.is_duplicate(&h5));
        assert_eq!(hl.len(), 3);
    }

    #[test]
    fn test_zero_capacity_hashlist_is_noop() {
        let mut hl = PacketHashlist::new(0);
        let h = make_hash(1);

        hl.add(h);

        assert_eq!(hl.len(), 0);
        assert!(!hl.is_duplicate(&h));
    }
}
