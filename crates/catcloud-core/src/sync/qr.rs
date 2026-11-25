use crate::{CatError, CatResult};

/// QR error correction level supported by CatCloud sync codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EccLevel {
    L,
    M,
}

impl EccLevel {
    fn format_bits(self) -> u32 {
        match self {
            Self::L => 0b01,
            Self::M => 0b00,
        }
    }
}

/// Rendered QR matrix (Version 1–15, ISO/IEC 18004 Byte mode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrMatrix {
    pub version: u8,
    pub ecc: EccLevel,
    pub size: usize,
    /// Row-major `size * size` grid (`true` = dark module, `false` = light module).
    pub modules: Vec<bool>,
}

impl QrMatrix {
    #[inline]
    pub fn get(&self, x: usize, y: usize) -> bool {
        self.modules[y * self.size + x]
    }
}

#[derive(Debug, Clone, Copy)]
struct VersionSpec {
    version: u8,
    total_codewords: usize,
    ec_cw_per_block: usize,
    num_blocks: usize,
}

impl VersionSpec {
    fn total_data_codewords(self) -> usize {
        self.total_codewords - self.ec_cw_per_block * self.num_blocks
    }

    fn max_byte_payload(self) -> usize {
        let count_bits = if self.version <= 9 { 8 } else { 16 };
        // 4-bit Byte mode indicator (0100) + count_bits + 8*N <= total_data_codewords * 8
        let available_bits = self.total_data_codewords() * 8 - (4 + count_bits);
        available_bits / 8
    }

    fn block_layout(self) -> (usize, usize, usize, usize) {
        let total_data = self.total_data_codewords();
        let short_len = total_data / self.num_blocks;
        let long_blocks = total_data % self.num_blocks;
        let short_blocks = self.num_blocks - long_blocks;
        (short_blocks, short_len, long_blocks, short_len + 1)
    }
}

// ISO/IEC 18004 Table 9 — Version 1..=15, ECC Level L
const SPECS_L: [VersionSpec; 15] = [
    VersionSpec { version: 1, total_codewords: 26, ec_cw_per_block: 7, num_blocks: 1 },
    VersionSpec { version: 2, total_codewords: 44, ec_cw_per_block: 10, num_blocks: 1 },
    VersionSpec { version: 3, total_codewords: 70, ec_cw_per_block: 15, num_blocks: 1 },
    VersionSpec { version: 4, total_codewords: 100, ec_cw_per_block: 20, num_blocks: 1 },
    VersionSpec { version: 5, total_codewords: 134, ec_cw_per_block: 26, num_blocks: 1 },
    VersionSpec { version: 6, total_codewords: 172, ec_cw_per_block: 18, num_blocks: 2 },
    VersionSpec { version: 7, total_codewords: 196, ec_cw_per_block: 20, num_blocks: 2 },
    VersionSpec { version: 8, total_codewords: 242, ec_cw_per_block: 24, num_blocks: 2 },
    VersionSpec { version: 9, total_codewords: 292, ec_cw_per_block: 30, num_blocks: 2 },
    VersionSpec { version: 10, total_codewords: 346, ec_cw_per_block: 18, num_blocks: 4 },
    VersionSpec { version: 11, total_codewords: 404, ec_cw_per_block: 20, num_blocks: 4 },
    VersionSpec { version: 12, total_codewords: 466, ec_cw_per_block: 24, num_blocks: 4 },
    VersionSpec { version: 13, total_codewords: 532, ec_cw_per_block: 26, num_blocks: 4 },
    VersionSpec { version: 14, total_codewords: 581, ec_cw_per_block: 30, num_blocks: 4 },
    VersionSpec { version: 15, total_codewords: 655, ec_cw_per_block: 22, num_blocks: 6 },
];

// ISO/IEC 18004 Table 9 — Version 1..=15, ECC Level M
const SPECS_M: [VersionSpec; 15] = [
    VersionSpec { version: 1, total_codewords: 26, ec_cw_per_block: 10, num_blocks: 1 },
    VersionSpec { version: 2, total_codewords: 44, ec_cw_per_block: 16, num_blocks: 1 },
    VersionSpec { version: 3, total_codewords: 70, ec_cw_per_block: 26, num_blocks: 1 },
    VersionSpec { version: 4, total_codewords: 100, ec_cw_per_block: 18, num_blocks: 2 },
    VersionSpec { version: 5, total_codewords: 134, ec_cw_per_block: 24, num_blocks: 2 },
    VersionSpec { version: 6, total_codewords: 172, ec_cw_per_block: 16, num_blocks: 4 },
    VersionSpec { version: 7, total_codewords: 196, ec_cw_per_block: 18, num_blocks: 4 },
    VersionSpec { version: 8, total_codewords: 242, ec_cw_per_block: 22, num_blocks: 4 },
    VersionSpec { version: 9, total_codewords: 292, ec_cw_per_block: 22, num_blocks: 5 },
    VersionSpec { version: 10, total_codewords: 346, ec_cw_per_block: 26, num_blocks: 5 },
    VersionSpec { version: 11, total_codewords: 404, ec_cw_per_block: 30, num_blocks: 5 },
    VersionSpec { version: 12, total_codewords: 466, ec_cw_per_block: 22, num_blocks: 8 },
    VersionSpec { version: 13, total_codewords: 532, ec_cw_per_block: 22, num_blocks: 9 },
    VersionSpec { version: 14, total_codewords: 581, ec_cw_per_block: 24, num_blocks: 9 },
    VersionSpec { version: 15, total_codewords: 655, ec_cw_per_block: 24, num_blocks: 10 },
];

fn alignment_centers(version: u8) -> &'static [usize] {
    match version {
        1 => &[],
        2 => &[6, 18],
        3 => &[6, 22],
        4 => &[6, 26],
        5 => &[6, 30],
        6 => &[6, 34],
        7 => &[6, 22, 38],
        8 => &[6, 24, 42],
        9 => &[6, 26, 46],
        10 => &[6, 28, 50],
        11 => &[6, 30, 54],
        12 => &[6, 32, 58],
        13 => &[6, 34, 62],
        14 => &[6, 26, 46, 66],
        15 => &[6, 26, 48, 70],
        _ => &[],
    }
}

/// GF(256) multiplication modulo primitive polynomial `x^8 + x^4 + x^3 + x^2 + 1` (`0x11D`).
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    for _ in 0..8 {
        if (b & 1) != 0 {
            result ^= a;
        }
        let hi = (a & 0x80) != 0;
        a <<= 1;
        if hi {
            a ^= 0x1d;
        }
        b >>= 1;
    }
    result
}

/// Build RS generator polynomial `prod_{i=0..degree} (x - alpha^i)` returning coefficients
/// `[c_0, c_1, ..., c_{degree-1}]` omitting the monic leading `x^degree` term.
fn rs_generator_poly(degree: usize) -> Vec<u8> {
    let mut poly = vec![0u8; degree];
    poly[degree - 1] = 1;
    let mut root = 1u8;
    for _ in 0..degree {
        for j in 0..degree {
            poly[j] = gf_mul(poly[j], root);
            if j + 1 < degree {
                poly[j] ^= poly[j + 1];
            }
        }
        root = gf_mul(root, 0x02);
    }
    poly
}

/// Compute `degree` Reed-Solomon error correction codewords for `data`.
fn rs_compute_remainder(data: &[u8], generator: &[u8]) -> Vec<u8> {
    let mut rem = vec![0u8; generator.len()];
    for &byte in data {
        let factor = byte ^ rem[0];
        rem.rotate_left(1);
        *rem.last_mut().unwrap() = 0;
        for (r, &g) in rem.iter_mut().zip(generator.iter()) {
            *r ^= gf_mul(g, factor);
        }
    }
    rem
}

fn select_spec(byte_len: usize, ecc: EccLevel) -> CatResult<VersionSpec> {
    let table = match ecc {
        EccLevel::L => &SPECS_L,
        EccLevel::M => &SPECS_M,
    };
    table
        .iter()
        .copied()
        .find(|spec| byte_len <= spec.max_byte_payload())
        .ok_or_else(|| {
            CatError::Validation(format!(
                "QR payload length {byte_len} bytes exceeds max supported capacity (Version 15 {:?}: {} bytes)",
                ecc,
                table.last().unwrap().max_byte_payload()
            ))
        })
}

fn encode_data_codewords(payload: &[u8], spec: VersionSpec) -> Vec<u8> {
    let total_data_cw = spec.total_data_codewords();
    let total_data_bits = total_data_cw * 8;
    let mut bits: Vec<bool> = Vec::with_capacity(total_data_bits);

    let push_bits = |buf: &mut Vec<bool>, value: u32, width: usize| {
        for shift in (0..width).rev() {
            buf.push(((value >> shift) & 1) != 0);
        }
    };

    // Byte mode indicator: 0100
    push_bits(&mut bits, 0b0100, 4);
    // Character count indicator
    let count_width = if spec.version <= 9 { 8 } else { 16 };
    push_bits(&mut bits, payload.len() as u32, count_width);
    // Payload bytes
    for &byte in payload {
        push_bits(&mut bits, byte as u32, 8);
    }
    // Terminator (up to 4 zero bits)
    let term_len = (total_data_bits - bits.len()).min(4);
    bits.resize(bits.len() + term_len, false);
    // Pad to byte boundary
    while bits.len() % 8 != 0 {
        bits.push(false);
    }

    let mut codewords = Vec::with_capacity(total_data_cw);
    for chunk in bits.chunks_exact(8) {
        let mut byte = 0u8;
        for &b in chunk {
            byte = (byte << 1) | u8::from(b);
        }
        codewords.push(byte);
    }

    // Pad codewords alternating 0xEC, 0x11
    let mut pad_idx = 0usize;
    while codewords.len() < total_data_cw {
        codewords.push(if pad_idx % 2 == 0 { 0xEC } else { 0x11 });
        pad_idx += 1;
    }
    codewords
}

fn interleave_blocks(data_cw: &[u8], spec: VersionSpec) -> Vec<u8> {
    let (short_blocks, short_len, long_blocks, long_len) = spec.block_layout();
    let generator = rs_generator_poly(spec.ec_cw_per_block);

    let mut data_blocks: Vec<&[u8]> = Vec::with_capacity(spec.num_blocks);
    let mut ec_blocks: Vec<Vec<u8>> = Vec::with_capacity(spec.num_blocks);

    let mut offset = 0usize;
    for i in 0..spec.num_blocks {
        let blk_len = if i < short_blocks { short_len } else { long_len };
        let blk = &data_cw[offset..offset + blk_len];
        offset += blk_len;
        ec_blocks.push(rs_compute_remainder(blk, &generator));
        data_blocks.push(blk);
    }
    debug_assert_eq!(offset, data_cw.len());

    let max_data_len = if long_blocks > 0 { long_len } else { short_len };
    let mut out = Vec::with_capacity(spec.total_codewords);
    for i in 0..max_data_len {
        for blk in &data_blocks {
            if i < blk.len() {
                out.push(blk[i]);
            }
        }
    }
    for i in 0..spec.ec_cw_per_block {
        for ec in &ec_blocks {
            out.push(ec[i]);
        }
    }
    debug_assert_eq!(out.len(), spec.total_codewords);
    out
}

fn format_info_bits(ecc: EccLevel, mask: u8) -> u32 {
    let data = (ecc.format_bits() << 3) | u32::from(mask);
    let mut rem = data << 10;
    for i in (0..5).rev() {
        if ((rem >> (i + 10)) & 1) != 0 {
            rem ^= 0x537 << i;
        }
    }
    ((data << 10) | rem) ^ 0x5412
}

fn version_info_bits(version: u8) -> u32 {
    let data = u32::from(version);
    let mut rem = data << 12;
    for i in (0..6).rev() {
        if ((rem >> (i + 12)) & 1) != 0 {
            rem ^= 0x1F25 << i;
        }
    }
    (data << 12) | rem
}

struct GridBuilder {
    size: usize,
    modules: Vec<bool>,
    is_function: Vec<bool>,
}

impl GridBuilder {
    fn new(version: u8) -> Self {
        let size = 17 + 4 * usize::from(version);
        Self {
            size,
            modules: vec![false; size * size],
            is_function: vec![false; size * size],
        }
    }

    #[inline]
    fn set_function(&mut self, x: usize, y: usize, dark: bool) {
        let idx = y * self.size + x;
        self.modules[idx] = dark;
        self.is_function[idx] = true;
    }

    fn draw_finder_with_separator(&mut self, origin_x: usize, origin_y: usize) {
        let min_x = origin_x.saturating_sub(1);
        let max_x = (origin_x + 7).min(self.size - 1);
        let min_y = origin_y.saturating_sub(1);
        let max_y = (origin_y + 7).min(self.size - 1);

        for y in min_y..=max_y {
            for x in min_x..=max_x {
                let inside =
                    x >= origin_x && x < origin_x + 7 && y >= origin_y && y < origin_y + 7;
                if !inside {
                    self.set_function(x, y, false);
                } else {
                    let dx = (x - origin_x) as isize - 3;
                    let dy = (y - origin_y) as isize - 3;
                    let dist = dx.abs().max(dy.abs());
                    let dark = dist != 2;
                    self.set_function(x, y, dark);
                }
            }
        }
    }

    fn draw_alignment(&mut self, cx: usize, cy: usize) {
        for dy in -2isize..=2 {
            for dx in -2isize..=2 {
                let dist = dx.abs().max(dy.abs());
                let dark = dist != 1;
                self.set_function((cx as isize + dx) as usize, (cy as isize + dy) as usize, dark);
            }
        }
    }

    fn draw_function_patterns(&mut self, version: u8) {
        let n = self.size;
        // 1. Timing patterns
        for i in 0..n {
            let dark = i % 2 == 0;
            self.set_function(i, 6, dark);
            self.set_function(6, i, dark);
        }

        // 2. Three Finder patterns + 1-module white separators
        self.draw_finder_with_separator(0, 0);
        self.draw_finder_with_separator(n - 7, 0);
        self.draw_finder_with_separator(0, n - 7);

        // 3. Alignment patterns (V >= 2)
        let centers = alignment_centers(version);
        if let Some(&last) = centers.last() {
            for &cy in centers {
                for &cx in centers {
                    let overlaps_finder =
                        (cx == 6 && cy == 6) || (cx == 6 && cy == last) || (cx == last && cy == 6);
                    if !overlaps_finder {
                        self.draw_alignment(cx, cy);
                    }
                }
            }
        }

        // 4. Reserve Format Info areas (written properly per candidate mask)
        self.write_format_info(0);
        // Dark module at (8, 4*version + 9) == (8, n - 8)
        self.set_function(8, n - 8, true);

        // 5. Version Info (V >= 7)
        if version >= 7 {
            let vbits = version_info_bits(version);
            for i in 0..18usize {
                let dark = ((vbits >> i) & 1) != 0;
                let a = n - 11 + (i % 3);
                let b = i / 3;
                self.set_function(a, b, dark);
                self.set_function(b, a, dark);
            }
        }
    }

    fn write_format_info(&mut self, bits: u32) {
        let n = self.size;
        // Copy 1: around top-left finder (bit 14 MSB -> bit 0 LSB)
        let copy1_coords: [(usize, usize); 15] = [
            (0, 8),
            (1, 8),
            (2, 8),
            (3, 8),
            (4, 8),
            (5, 8),
            (7, 8),
            (8, 8),
            (8, 7),
            (8, 5),
            (8, 4),
            (8, 3),
            (8, 2),
            (8, 1),
            (8, 0),
        ];
        // Copy 2: bottom-left vertical (bits 14..=8) + top-right horizontal (bits 7..=0)
        let copy2_coords: [(usize, usize); 15] = [
            (8, n - 1),
            (8, n - 2),
            (8, n - 3),
            (8, n - 4),
            (8, n - 5),
            (8, n - 6),
            (8, n - 7),
            (n - 8, 8),
            (n - 7, 8),
            (n - 6, 8),
            (n - 5, 8),
            (n - 4, 8),
            (n - 3, 8),
            (n - 2, 8),
            (n - 1, 8),
        ];
        for i in 0..15usize {
            let bit = ((bits >> (14 - i)) & 1) != 0;
            let (x1, y1) = copy1_coords[i];
            let (x2, y2) = copy2_coords[i];
            self.set_function(x1, y1, bit);
            self.set_function(x2, y2, bit);
        }
    }

    fn place_codewords(&mut self, all_codewords: &[u8]) {
        let n = self.size;
        let total_bits = all_codewords.len() * 8;
        let mut bit_idx = 0usize;
        let mut col = n as isize - 1;
        let mut upward = true;

        while col > 0 {
            if col == 6 {
                col -= 1;
            }
            for step in 0..n {
                let y = if upward { n - 1 - step } else { step };
                for dx in 0..2 {
                    let x = (col - dx) as usize;
                    let idx = y * n + x;
                    if !self.is_function[idx] {
                        let dark = if bit_idx < total_bits {
                            let byte = all_codewords[bit_idx >> 3];
                            let shift = 7 - (bit_idx & 7);
                            bit_idx += 1;
                            ((byte >> shift) & 1) != 0
                        } else {
                            // Remainder bits are always 0 (light)
                            false
                        };
                        self.modules[idx] = dark;
                    }
                }
            }
            upward = !upward;
            col -= 2;
        }
        debug_assert_eq!(bit_idx, total_bits);
    }

    fn apply_mask_and_score(&self, ecc: EccLevel, mask: u8) -> (Vec<bool>, u32) {
        let n = self.size;
        let mut grid = self.modules.clone();
        for y in 0..n {
            for x in 0..n {
                let idx = y * n + x;
                if !self.is_function[idx] && mask_matches(mask, x, y) {
                    grid[idx] = !grid[idx];
                }
            }
        }

        // Write format info for this mask
        let fbits = format_info_bits(ecc, mask);
        let copy1_coords: [(usize, usize); 15] = [
            (0, 8),
            (1, 8),
            (2, 8),
            (3, 8),
            (4, 8),
            (5, 8),
            (7, 8),
            (8, 8),
            (8, 7),
            (8, 5),
            (8, 4),
            (8, 3),
            (8, 2),
            (8, 1),
            (8, 0),
        ];
        let copy2_coords: [(usize, usize); 15] = [
            (8, n - 1),
            (8, n - 2),
            (8, n - 3),
            (8, n - 4),
            (8, n - 5),
            (8, n - 6),
            (8, n - 7),
            (n - 8, 8),
            (n - 7, 8),
            (n - 6, 8),
            (n - 5, 8),
            (n - 4, 8),
            (n - 3, 8),
            (n - 2, 8),
            (n - 1, 8),
        ];
        for i in 0..15usize {
            let bit = ((fbits >> (14 - i)) & 1) != 0;
            let (x1, y1) = copy1_coords[i];
            let (x2, y2) = copy2_coords[i];
            grid[y1 * n + x1] = bit;
            grid[y2 * n + x2] = bit;
        }

        let penalty = evaluate_penalty(&grid, n);
        (grid, penalty)
    }
}

#[inline]
fn mask_matches(mask: u8, x: usize, y: usize) -> bool {
    match mask {
        0 => (y + x) % 2 == 0,
        1 => y % 2 == 0,
        2 => x % 3 == 0,
        3 => (y + x) % 3 == 0,
        4 => ((y / 2) + (x / 3)) % 2 == 0,
        5 => ((y * x) % 2) + ((y * x) % 3) == 0,
        6 => (((y * x) % 2) + ((y * x) % 3)) % 2 == 0,
        7 => (((y + x) % 2) + ((y * x) % 3)) % 2 == 0,
        _ => false,
    }
}

fn evaluate_penalty(grid: &[bool], n: usize) -> u32 {
    let mut penalty = 0u32;

    // Rule 1: Adjacent modules in row/column in same color (>= 5 -> 3 + len - 5)
    for y in 0..n {
        let mut run_color = grid[y * n];
        let mut run_len = 1u32;
        for x in 1..n {
            let c = grid[y * n + x];
            if c == run_color {
                run_len += 1;
            } else {
                if run_len >= 5 {
                    penalty += 3 + (run_len - 5);
                }
                run_color = c;
                run_len = 1;
            }
        }
        if run_len >= 5 {
            penalty += 3 + (run_len - 5);
        }
    }
    for x in 0..n {
        let mut run_color = grid[x];
        let mut run_len = 1u32;
        for y in 1..n {
            let c = grid[y * n + x];
            if c == run_color {
                run_len += 1;
            } else {
                if run_len >= 5 {
                    penalty += 3 + (run_len - 5);
                }
                run_color = c;
                run_len = 1;
            }
        }
        if run_len >= 5 {
            penalty += 3 + (run_len - 5);
        }
    }

    // Rule 2: 2x2 blocks of same color (+3 each)
    for y in 0..(n - 1) {
        for x in 0..(n - 1) {
            let c = grid[y * n + x];
            if c == grid[y * n + x + 1]
                && c == grid[(y + 1) * n + x]
                && c == grid[(y + 1) * n + x + 1]
            {
                penalty += 3;
            }
        }
    }

    // Rule 3: Finder-like 1:1:3:1:1 ratio with 4 light modules on either side (+40 each)
    const PAT_A: [bool; 11] = [
        true, false, true, true, true, false, true, false, false, false, false,
    ];
    const PAT_B: [bool; 11] = [
        false, false, false, false, true, false, true, true, true, false, true,
    ];
    if n >= 11 {
        for y in 0..n {
            let row = &grid[y * n..(y + 1) * n];
            for x in 0..=(n - 11) {
                let slice = &row[x..x + 11];
                if slice == PAT_A || slice == PAT_B {
                    penalty += 40;
                }
            }
        }
        for x in 0..n {
            for y in 0..=(n - 11) {
                let mut match_a = true;
                let mut match_b = true;
                for k in 0..11 {
                    let c = grid[(y + k) * n + x];
                    if c != PAT_A[k] {
                        match_a = false;
                    }
                    if c != PAT_B[k] {
                        match_b = false;
                    }
                    if !match_a && !match_b {
                        break;
                    }
                }
                if match_a || match_b {
                    penalty += 40;
                }
            }
        }
    }

    // Rule 4: Balance of dark and light modules
    let dark_count = grid.iter().filter(|&&b| b).count();
    let total = n * n;
    let k = (dark_count * 20).abs_diff(total * 10) / total;
    penalty += (k as u32) * 10;

    penalty
}

/// Encode UTF-8 text into a standard QR matrix using ECC Level L (Byte mode, Version 1–15).
pub fn encode_qr_matrix(text: &str) -> CatResult<QrMatrix> {
    encode_qr_matrix_with_ecc(text, EccLevel::L)
}

/// Encode UTF-8 text into a standard QR matrix with explicit ECC level (L or M).
pub fn encode_qr_matrix_with_ecc(text: &str, ecc: EccLevel) -> CatResult<QrMatrix> {
    let payload = text.as_bytes();
    let spec = select_spec(payload.len(), ecc)?;
    let data_cw = encode_data_codewords(payload, spec);
    let interleaved = interleave_blocks(&data_cw, spec);

    let mut builder = GridBuilder::new(spec.version);
    builder.draw_function_patterns(spec.version);
    builder.place_codewords(&interleaved);

    let mut best_modules: Option<Vec<bool>> = None;
    let mut best_penalty = u32::MAX;
    for mask in 0..8u8 {
        let (candidate, penalty) = builder.apply_mask_and_score(ecc, mask);
        if penalty < best_penalty {
            best_penalty = penalty;
            best_modules = Some(candidate);
        }
    }

    Ok(QrMatrix {
        version: spec.version,
        ecc,
        size: builder.size,
        modules: best_modules.unwrap(),
    })
}

/// Render a minimal crisp `<svg><rect .../><path .../></svg>` QR code with 4-module quiet zone.
pub fn render_qr_svg(text: &str) -> CatResult<String> {
    render_qr_svg_with_ecc(text, EccLevel::L)
}

/// Render SVG QR code with explicit ECC level.
pub fn render_qr_svg_with_ecc(text: &str, ecc: EccLevel) -> CatResult<String> {
    let matrix = encode_qr_matrix_with_ecc(text, ecc)?;
    let quiet = 4usize;
    let total = matrix.size + quiet * 2;

    let mut path = String::with_capacity(matrix.size * matrix.size * 6);
    for y in 0..matrix.size {
        let mut x = 0usize;
        while x < matrix.size {
            if matrix.get(x, y) {
                let start = x;
                while x < matrix.size && matrix.get(x, y) {
                    x += 1;
                }
                let run = x - start;
                use std::fmt::Write as _;
                let _ = write!(path, "M{},{}h{}v1h-{}z", start + quiet, y + quiet, run, run);
            } else {
                x += 1;
            }
        }
    }

    Ok(format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total} {total}" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#ffffff"/><path d="{path}" fill="#000000"/></svg>"##
    ))
}

/// Render a compact UTF-8 terminal QR code using half-block characters (`▀`, `▄`, `█`, ` `).
pub fn render_qr_terminal(text: &str) -> CatResult<String> {
    render_qr_terminal_with_ecc(text, EccLevel::L)
}

/// Render UTF-8 terminal QR code with explicit ECC level.
pub fn render_qr_terminal_with_ecc(text: &str, ecc: EccLevel) -> CatResult<String> {
    let matrix = encode_qr_matrix_with_ecc(text, ecc)?;
    let quiet = 2usize;
    let total = matrix.size + quiet * 2;
    let at = |x: usize, y: usize| -> bool {
        if x < quiet || y < quiet || x >= quiet + matrix.size || y >= quiet + matrix.size {
            false
        } else {
            matrix.get(x - quiet, y - quiet)
        }
    };

    let mut out = String::with_capacity((total + 1) * ((total + 1) / 2) * 3);
    let mut y = 0usize;
    while y < total {
        if y > 0 {
            out.push('\n');
        }
        for x in 0..total {
            let top = at(x, y);
            let bot = if y + 1 < total { at(x, y + 1) } else { false };
            let ch = match (top, bot) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            };
            out.push(ch);
        }
        y += 2;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gf_pow_alpha(exp: usize) -> u8 {
        let mut val = 1u8;
        for _ in 0..exp {
            val = gf_mul(val, 0x02);
        }
        val
    }

    fn eval_poly_gf(coeffs: &[u8], x: u8) -> u8 {
        let mut acc = 0u8;
        for &c in coeffs {
            acc = gf_mul(acc, x) ^ c;
        }
        acc
    }

    #[test]
    fn reed_solomon_syndromes_are_zero_for_all_versions_and_levels() {
        for &ecc in &[EccLevel::L, EccLevel::M] {
            let table = match ecc {
                EccLevel::L => &SPECS_L,
                EccLevel::M => &SPECS_M,
            };
            for &spec in table {
                let gen_poly = rs_generator_poly(spec.ec_cw_per_block);
                let sample: Vec<u8> = (0..spec.total_data_codewords())
                    .map(|i| ((i * 37 + 13) & 0xff) as u8)
                    .collect();
                let (g1, k1, _g2, k2) = spec.block_layout();
                let mut offset = 0usize;
                for blk_idx in 0..spec.num_blocks {
                    let len = if blk_idx < g1 { k1 } else { k2 };
                    let data = &sample[offset..offset + len];
                    offset += len;
                    let ec = rs_compute_remainder(data, &gen_poly);
                    assert_eq!(ec.len(), spec.ec_cw_per_block);
                    let mut codeword = Vec::with_capacity(data.len() + ec.len());
                    codeword.extend_from_slice(data);
                    codeword.extend_from_slice(&ec);
                    for root_exp in 0..spec.ec_cw_per_block {
                        let syn = eval_poly_gf(&codeword, gf_pow_alpha(root_exp));
                        assert_eq!(
                            syn, 0,
                            "non-zero RS syndrome for V{} {:?} block {} root alpha^{}",
                            spec.version, ecc, blk_idx, root_exp
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn bch_format_and_version_bits_match_iso18004_tables() {
        // Table C.1
        assert_eq!(format_info_bits(EccLevel::M, 0), 0x5412);
        assert_eq!(format_info_bits(EccLevel::L, 0), 0x77c4);
        assert_eq!(format_info_bits(EccLevel::L, 1), 0x72f3);
        assert_eq!(format_info_bits(EccLevel::M, 4), 0x45f9);
        // Table D.1
        assert_eq!(version_info_bits(7), 0x07c94);
        assert_eq!(version_info_bits(12), 0x0c762);
        assert_eq!(version_info_bits(15), 0x0f928);
    }

    fn assert_finder_and_timing(m: &QrMatrix) {
        let n = m.size;
        // Three 7x7 finder centers & borders
        for &(ox, oy) in &[(0usize, 0usize), (n - 7, 0), (0, n - 7)] {
            for dy in 0..7 {
                for dx in 0..7 {
                    let dist = (dx as isize - 3).abs().max((dy as isize - 3).abs());
                    let expected = dist != 2;
                    assert_eq!(
                        m.get(ox + dx, oy + dy),
                        expected,
                        "finder mismatch at ({},{}) for V{}",
                        ox + dx,
                        oy + dy,
                        m.version
                    );
                }
            }
        }
        // Dark module
        assert!(m.get(8, n - 8));
        // Timing lines
        for i in 8..(n - 8) {
            assert_eq!(m.get(i, 6), i % 2 == 0);
            assert_eq!(m.get(6, i), i % 2 == 0);
        }
        // Format info copies must be bit-identical
        let c1 = [
            (0, 8), (1, 8), (2, 8), (3, 8), (4, 8), (5, 8), (7, 8), (8, 8),
            (8, 7), (8, 5), (8, 4), (8, 3), (8, 2), (8, 1), (8, 0),
        ];
        let c2 = [
            (8, n - 1), (8, n - 2), (8, n - 3), (8, n - 4), (8, n - 5), (8, n - 6), (8, n - 7),
            (n - 8, 8), (n - 7, 8), (n - 6, 8), (n - 5, 8), (n - 4, 8), (n - 3, 8), (n - 2, 8),
            (n - 1, 8),
        ];
        for i in 0..15 {
            assert_eq!(
                m.get(c1[i].0, c1[i].1),
                m.get(c2[i].0, c2[i].1),
                "format bit {i} mismatch between copy 1 and copy 2"
            );
        }
    }

    #[test]
    fn version_boundaries_and_typical_sync_uri() {
        // V1 max L = 17, V4 max L = 78, V7 max L = 154, V12 max L = 367, V15 max L = 520
        for &(len, expected_v) in &[
            (17usize, 1u8),
            (18, 2),
            (78, 4),
            (154, 7),
            (367, 12),
            (520, 15),
        ] {
            let payload = "A".repeat(len);
            let m = encode_qr_matrix(&payload).unwrap();
            assert_eq!(m.version, expected_v, "length {len} expected V{expected_v}");
            assert_eq!(m.size, 17 + 4 * usize::from(expected_v));
            assert_finder_and_timing(&m);
        }

        // Over V15 capacity rejected cleanly
        assert!(encode_qr_matrix(&"A".repeat(521)).is_err());

        // Typical ~220-byte catcloud://sync/v1 URI
        let sample_uri = "catcloud://sync/v1?role=pull&ep=https%3A%2F%2Fsync.demo.example.com%3A8443&hosts=192.168.1.105,192.168.31.42,10.0.0.15&port=49152&sid=0123456789abcdef&fp=0123456789abcdef#k=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(sample_uri.len() >= 200);
        let qr = encode_qr_matrix(sample_uri).unwrap();
        assert_finder_and_timing(&qr);
        let svg = render_qr_svg(sample_uri).unwrap();
        assert!(svg.starts_with("<svg ") && svg.ends_with("</svg>") && svg.contains("<path d="));
        let term = render_qr_terminal(sample_uri).unwrap();
        assert!(term.contains('█') || term.contains('▀') || term.contains('▄'));
        println!(
            "TYPICAL_QR_URI_LEN={} VERSION={} SIZE={}x{} SVG_BYTES={}",
            sample_uri.len(),
            qr.version,
            qr.size,
            qr.size,
            svg.len()
        );
    }

    #[test]
    fn ecc_level_m_supports_group1_group2_interleaving() {
        let payload = "M".repeat(220);
        let m = encode_qr_matrix_with_ecc(&payload, EccLevel::M).unwrap();
        assert_eq!(m.ecc, EccLevel::M);
        assert_eq!(m.version, 11); // V10-M max=213, V11-M max=251
        assert_finder_and_timing(&m);
    }
}
