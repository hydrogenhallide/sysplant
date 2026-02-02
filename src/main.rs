use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use ratatui::{
    prelude::*,
    style::Color,
    widgets::{Block, Borders, Paragraph},
};
use sha2::{Digest, Sha256};
use std::io::{stdout, Result};

// ============================================================================
// SYSTEM FINGERPRINT
// ============================================================================

#[derive(Debug, Clone)]
struct SystemFingerprint {
    machine_id: String,
    os: String,
    distro: String,
    distro_color: Option<Color>,
    kernel: String,
    hostname: String,
    username: String,
    arch: String,
}

impl SystemFingerprint {
    fn collect() -> Self {
        // All values have deterministic fallbacks
        let machine_id = Self::get_machine_id();
        let os = if std::env::consts::OS.is_empty() { "unknown" } else { std::env::consts::OS }.to_string();
        let hostname = whoami::fallible::hostname().unwrap_or_else(|_| "localhost".to_string());
        let username = whoami::fallible::username().unwrap_or_else(|_| "user".to_string());
        let arch = if std::env::consts::ARCH.is_empty() { "unknown" } else { std::env::consts::ARCH }.to_string();
        let (distro, distro_color) = Self::get_distro_info();
        let kernel = Self::get_kernel();

        Self {
            machine_id,
            os,
            distro,
            distro_color,
            kernel,
            hostname,
            username,
            arch,
        }
    }

    fn get_machine_id() -> String {
        // Try /etc/machine-id (Linux, systemd)
        if let Ok(content) = std::fs::read_to_string("/etc/machine-id") {
            let trimmed = content.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        // Try /var/lib/dbus/machine-id (older systems)
        if let Ok(content) = std::fs::read_to_string("/var/lib/dbus/machine-id") {
            let trimmed = content.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        // Fallback: use hostname + os
        format!("{}-{}", std::env::consts::OS, whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string()))
    }

    // Base seed from machine-id - determines core plant structure
    fn base_seed(&self) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(&self.machine_id);
        let hash: [u8; 32] = hasher.finalize().into();
        u64::from_le_bytes(hash[0..8].try_into().unwrap())
    }

    // Modifier from a string - returns value between -0.15 and 0.15
    fn modifier(s: &str) -> f32 {
        let mut hasher = Sha256::new();
        hasher.update(s);
        let hash: [u8; 32] = hasher.finalize().into();
        let val = u32::from_le_bytes(hash[0..4].try_into().unwrap());
        (val as f32 / u32::MAX as f32) * 0.3 - 0.15
    }

    // Index from a string - returns value between 0 and max
    fn index(s: &str, max: usize) -> usize {
        let mut hasher = Sha256::new();
        hasher.update(s);
        let hash: [u8; 32] = hasher.finalize().into();
        let val = u32::from_le_bytes(hash[0..4].try_into().unwrap());
        (val as usize) % max
    }

    // Bool from a string
    fn flag(s: &str) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(s);
        let hash: [u8; 32] = hasher.finalize().into();
        hash[0] > 127
    }

    fn get_distro_info() -> (String, Option<Color>) {
        // Try /etc/os-release first (Linux)
        if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
            let mut distro = String::new();
            let mut ansi_color = None;

            for line in content.lines() {
                if line.starts_with("ID=") {
                    distro = line.get(3..).unwrap_or("").trim_matches('"').to_string();
                } else if line.starts_with("ANSI_COLOR=") {
                    if let Some(color_str) = line.get(11..) {
                        ansi_color = Self::parse_ansi_color(color_str.trim_matches('"'));
                    }
                }
            }

            if !distro.is_empty() {
                return (distro, ansi_color);
            }
        }
        // Try /etc/lsb-release as fallback
        if let Ok(content) = std::fs::read_to_string("/etc/lsb-release") {
            for line in content.lines() {
                if line.starts_with("DISTRIB_ID=") {
                    let distro = line.get(11..).unwrap_or("").trim_matches('"').to_lowercase();
                    if !distro.is_empty() {
                        return (distro, None);
                    }
                }
            }
        }
        // Use OS as fallback
        let os = std::env::consts::OS;
        if !os.is_empty() {
            return (os.to_string(), None);
        }
        ("generic".to_string(), None)
    }

    fn parse_ansi_color(color_str: &str) -> Option<Color> {
        // ANSI_COLOR format is like "0;31" or "1;34"
        // First number is bold/normal, second is color code
        // 30=black, 31=red, 32=green, 33=yellow, 34=blue, 35=magenta, 36=cyan, 37=white
        let parts: Vec<&str> = color_str.split(';').collect();
        let color_code = if parts.len() >= 2 {
            parts[1].parse::<u8>().ok()
        } else if parts.len() == 1 {
            parts[0].parse::<u8>().ok()
        } else {
            None
        };

        let is_bright = parts.first().map(|&s| s == "1").unwrap_or(false);

        match color_code {
            Some(30) => Some(if is_bright { Color::DarkGray } else { Color::Black }),
            Some(31) => Some(if is_bright { Color::LightRed } else { Color::Red }),
            Some(32) => Some(if is_bright { Color::LightGreen } else { Color::Green }),
            Some(33) => Some(if is_bright { Color::LightYellow } else { Color::Yellow }),
            Some(34) => Some(if is_bright { Color::LightBlue } else { Color::Blue }),
            Some(35) => Some(if is_bright { Color::LightMagenta } else { Color::Magenta }),
            Some(36) => Some(if is_bright { Color::LightCyan } else { Color::Cyan }),
            Some(37) => Some(if is_bright { Color::White } else { Color::Gray }),
            _ => None,
        }
    }

    fn get_kernel() -> String {
        // Try /proc/version (Linux)
        if let Ok(content) = std::fs::read_to_string("/proc/version") {
            if !content.is_empty() {
                // Extract just the version number (e.g., "6.17.13")
                if let Some(start) = content.find("version ") {
                    let rest = &content[start + 8..];
                    if let Some(end) = rest.find(|c: char| c.is_whitespace()) {
                        let version = rest[..end].to_string();
                        if !version.is_empty() {
                            return version;
                        }
                    }
                }
                // Fallback: first 50 chars
                return content.chars().take(50).collect();
            }
        }
        // Try /proc/sys/kernel/osrelease
        if let Ok(content) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
            let trimmed = content.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        // Deterministic fallback
        "generic".to_string()
    }
}

// ============================================================================
// PLANT DNA - Continuous parameters that define the plant's form
// ============================================================================

#[derive(Debug, Clone)]
struct PlantDna {
    // Growth form - these determine the basic body plan
    stem_count: u32,       // 1 = single trunk, 2+ = multiple stems (bush/grass)
    growth_habit: f32,     // 0.0 = ground-hugging (moss), 0.5 = bushy, 1.0 = upright (tree)
    height: f32,           // 0.3-1.0: how tall relative to canvas
    base_spread: f32,      // 0.0-1.0: how wide at the base (for multi-stem plants)

    // Trunk/stem structure
    trunk_thickness: f32,  // 0.0-1.0: thin stem to thick trunk
    trunk_taper: f32,      // 0.0-1.0: how much trunk narrows toward top
    trunk_curve: f32,      // -1.0 to 1.0: lean direction and amount
    waviness: f32,         // 0.0-1.0: how wavy/curly the stems are (for vines/grass)

    // Branching
    branch_start: f32,     // 0.0-1.0: how far up trunk branches start
    branch_count: u32,     // 0-12: number of main branches (0 = no branches, like grass)
    branch_angle: f32,     // 0.1-1.5: spread angle in radians
    branch_length: f32,    // 0.2-1.0: relative to height
    branch_droop: f32,     // -0.5 to 0.5: upward to drooping
    sub_branches: u32,     // 0-3: levels of sub-branching

    // Foliage
    leaf_density: f32,     // 0.0-1.0: how many leaves
    leaf_size: f32,        // 0.0-1.0: small dots to large shapes
    leaf_char: char,       // character used for leaves
    crown_spread: f32,     // 0.0-1.0: tight to spreading crown
    crown_shape: f32,      // 0.0=round, 0.5=flat, 1.0=conical

    // Extras
    has_flowers: bool,
    flower_char: char,
    has_fruit: bool,
    fruit_char: char,

    // Colors
    trunk_color: Color,
    leaf_color: Color,
    accent_color: Color,
}

impl PlantDna {
    fn from_fingerprint(fp: &SystemFingerprint) -> Self {
        // Base RNG from machine-id - determines core plant structure
        let mut rng = ChaCha8Rng::seed_from_u64(fp.base_seed());

        // Core structure from machine-id (stable across users/distros on same machine)
        // Growth form - determines body plan
        let base_stem_count = rng.gen_range(1..=8);
        let base_growth_habit = rng.gen_range(0.0..1.0);
        let base_height = rng.gen_range(0.3..0.98);
        let base_base_spread = rng.gen_range(0.0..1.0);
        let base_waviness = rng.gen_range(0.0..1.0);

        // Structure
        let base_trunk_thickness = rng.gen_range(0.05..1.0);
        let base_branch_angle = rng.gen_range(0.3..1.4);
        let base_branch_count = rng.gen_range(0..=10);
        let base_leaf_density = rng.gen_range(0.4..1.0);
        let base_trunk_taper = rng.gen_range(0.0..0.8);
        let base_trunk_curve = rng.gen_range(-0.6..0.6);
        let base_branch_start = rng.gen_range(0.1..0.8);
        let base_branch_length = rng.gen_range(0.2..0.8);
        let base_branch_droop = rng.gen_range(-0.3..0.5);
        let base_sub_branches = rng.gen_range(0..=3);
        let base_crown_spread = rng.gen_range(0.3..1.0);
        let base_leaf_size = rng.gen_range(0.1..1.0);
        let base_crown_shape = rng.gen_range(0.0..1.0);

        // Apply subtle modifiers from other factors
        // hostname -> affects trunk (it's the machine's "posture")
        let height = (base_height + SystemFingerprint::modifier(&fp.hostname) * 0.5).clamp(0.3, 0.98);
        let trunk_curve = (base_trunk_curve + SystemFingerprint::modifier(&fp.hostname)).clamp(-0.8, 0.8);

        // kernel -> affects branches (the "nervous system")
        let branch_droop = (base_branch_droop + SystemFingerprint::modifier(&fp.kernel)).clamp(-0.4, 0.5);
        let sub_branches = ((base_sub_branches as i32) + if SystemFingerprint::flag(&fp.kernel) { 1 } else { 0 }).clamp(0, 3) as u32;

        // username -> affects flowers/fruit (personal touch)
        let has_flowers = SystemFingerprint::flag(&format!("flowers-{}", fp.username));
        let has_fruit = SystemFingerprint::flag(&format!("fruit-{}", fp.username));

        // arch -> affects leaf characteristics
        let leaf_size = (base_leaf_size + SystemFingerprint::modifier(&fp.arch)).clamp(0.0, 1.0);
        let crown_shape = (base_crown_shape + SystemFingerprint::modifier(&fp.arch)).clamp(0.0, 1.0);

        // Characters - distro influences these
        let leaf_chars = ['*', '#', 'o', '@', '%', '&', '+', 'x', 'O', 'w', 'm', 'W'];
        let flower_chars = ['*', '@', 'o', 'O', '0', 'Y', 'V', 'W'];
        let fruit_chars = ['o', 'O', '0', '@', 'a', 'Q'];

        let leaf_char = leaf_chars[SystemFingerprint::index(&fp.distro, leaf_chars.len())];
        let flower_char = flower_chars[SystemFingerprint::index(&format!("flower-{}", fp.distro), flower_chars.len())];
        let fruit_char = fruit_chars[SystemFingerprint::index(&format!("fruit-{}", fp.distro), fruit_chars.len())];

        // Colors - base from machine-id RNG, but ANSI_COLOR overrides leaf color
        let color_palette = [
            Color::Green, Color::LightGreen, Color::Yellow, Color::Cyan,
            Color::Magenta, Color::LightMagenta, Color::Red, Color::LightCyan,
            Color::LightYellow, Color::White, Color::LightBlue,
        ];

        let base_leaf_color = color_palette[rng.gen_range(0..color_palette.len())];
        let leaf_color = fp.distro_color.unwrap_or(base_leaf_color);

        // Accent color from RNG, shifted by username
        let accent_palette = [Color::Yellow, Color::Red, Color::LightRed, Color::Magenta, Color::White, Color::LightYellow, Color::Cyan, Color::LightMagenta];
        let accent_idx = (rng.gen_range(0..accent_palette.len()) + SystemFingerprint::index(&fp.username, accent_palette.len())) % accent_palette.len();
        let accent_color = accent_palette[accent_idx];

        // Trunk color - warm browns/tans from RNG
        let trunk_color = Color::Rgb(
            rng.gen_range(90..170),
            rng.gen_range(50..120),
            rng.gen_range(20..70),
        );

        // Adjust branch count based on growth form
        let adjusted_branches = if base_stem_count > 3 {
            // Multi-stem plants (bushes/grass) have fewer branches per stem
            base_branch_count.min(3)
        } else if base_trunk_thickness < 0.2 {
            // Very thin stems have fewer branches
            base_branch_count.min(4)
        } else {
            base_branch_count
        };

        // Waviness modified by kernel (system dynamics)
        let waviness = (base_waviness + SystemFingerprint::modifier(&fp.kernel) * 2.0).clamp(0.0, 1.0);

        Self {
            stem_count: base_stem_count,
            growth_habit: base_growth_habit,
            height,
            base_spread: base_base_spread,

            trunk_thickness: base_trunk_thickness,
            trunk_taper: base_trunk_taper,
            trunk_curve,
            waviness,

            branch_start: base_branch_start,
            branch_count: adjusted_branches,
            branch_angle: base_branch_angle,
            branch_length: base_branch_length,
            branch_droop,
            sub_branches,

            leaf_density: base_leaf_density,
            leaf_size,
            leaf_char,
            crown_spread: base_crown_spread,
            crown_shape,

            has_flowers,
            flower_char,
            has_fruit,
            fruit_char,

            trunk_color,
            leaf_color,
            accent_color,
        }
    }

    fn describe(&self) -> String {
        let mut traits = Vec::new();

        // Body plan description
        if self.growth_habit < 0.2 && self.height < 0.4 {
            traits.push("moss-like");
        } else if self.stem_count > 5 && self.trunk_thickness < 0.2 {
            traits.push("grassy");
        } else if self.stem_count > 3 {
            traits.push("bushy");
        } else if self.waviness > 0.6 && self.trunk_thickness < 0.3 {
            traits.push("vine-like");
        } else if self.trunk_thickness < 0.15 && self.branch_count <= 2 {
            traits.push("flowering");
        } else if self.trunk_thickness > 0.5 {
            traits.push("tree-like");
        }

        // Size
        if self.height > 0.8 {
            traits.push("tall");
        } else if self.height < 0.45 {
            traits.push("low");
        }

        // Character
        if self.branch_droop > 0.25 {
            traits.push("weeping");
        } else if self.branch_droop < -0.2 {
            traits.push("upright");
        }

        if self.waviness > 0.5 {
            traits.push("wavy");
        }

        if self.leaf_density > 0.85 {
            traits.push("lush");
        } else if self.leaf_density < 0.5 {
            traits.push("sparse");
        }

        if self.crown_spread > 0.75 {
            traits.push("spreading");
        }

        if self.has_flowers {
            traits.push("blooming");
        }

        if self.has_fruit {
            traits.push("fruiting");
        }

        if traits.is_empty() {
            "plant".to_string()
        } else {
            traits.join(", ")
        }
    }
}

// ============================================================================
// PLANT CANVAS
// ============================================================================

struct PlantCanvas {
    width: usize,
    height: usize,
    cells: Vec<Vec<(char, Color)>>,
}

impl PlantCanvas {
    fn new(width: usize, height: usize) -> Self {
        Self {
            width,
            height,
            cells: vec![vec![(' ', Color::Reset); width]; height],
        }
    }

    fn set(&mut self, x: i32, y: i32, ch: char, color: Color) {
        if x >= 0 && y >= 0 && (x as usize) < self.width && (y as usize) < self.height {
            // Don't overwrite with spaces
            if ch != ' ' || self.cells[y as usize][x as usize].0 == ' ' {
                self.cells[y as usize][x as usize] = (ch, color);
            }
        }
    }
}

// ============================================================================
// PLANT RENDERER - Unified algorithm driven by parameters
// ============================================================================

struct PlantRenderer {
    dna: PlantDna,
    rng: ChaCha8Rng,
}

impl PlantRenderer {
    fn new(dna: PlantDna, seed: u64) -> Self {
        Self {
            dna,
            rng: ChaCha8Rng::seed_from_u64(seed.wrapping_add(12345)),
        }
    }

    fn render(&mut self, canvas: &mut PlantCanvas) {
        let center_x = canvas.width as f32 / 2.0;
        let ground_y = canvas.height as i32 - 3;

        // Draw ground
        for x in 0..canvas.width as i32 {
            canvas.set(x, ground_y + 1, '=', Color::DarkGray);
        }

        // Draw pot (smaller for grass/moss)
        if self.dna.growth_habit > 0.3 || self.dna.stem_count <= 2 {
            self.draw_pot(canvas, center_x as i32, ground_y);
        }

        // Calculate plant dimensions
        let plant_height = ((canvas.height - 6) as f32 * self.dna.height) as i32;
        let trunk_top = ground_y - plant_height;

        // Multi-stem plants (bushes, grass, etc.)
        let stem_count = self.dna.stem_count;
        // Ensure minimum spread so multiple stems are actually visible
        let min_spread = if stem_count > 1 { 3.0 } else { 0.0 };
        let base_spread = (self.dna.base_spread * 12.0 + min_spread) as i32;

        let mut all_branch_points = Vec::new();

        for stem_idx in 0..stem_count {
            // Spread stems across the base
            let stem_offset = if stem_count == 1 {
                0.0
            } else {
                let spread_pos = stem_idx as f32 / (stem_count - 1) as f32; // 0.0 to 1.0
                (spread_pos - 0.5) * 2.0 * base_spread as f32
            };

            let stem_x = center_x + stem_offset;

            // Each stem can have slightly different height
            let stem_height_var = if stem_count > 1 {
                self.rng.gen_range(-0.15..0.15)
            } else {
                0.0
            };
            let this_stem_height = ((plant_height as f32) * (1.0 + stem_height_var)) as i32;
            let this_trunk_top = ground_y - this_stem_height;

            // Calculate divergence direction (-1 to +1, 0 for single stem)
            let divergence_dir = if stem_count == 1 {
                0.0
            } else {
                (stem_idx as f32 / (stem_count - 1) as f32 - 0.5) * 2.0
            };

            // Draw this stem and collect its branch points
            let branch_points = self.draw_stem(canvas, stem_x, ground_y as f32, this_trunk_top as f32, stem_idx, divergence_dir);
            all_branch_points.extend(branch_points);
        }

        let branch_points = all_branch_points;

        // Draw branches from each branch point
        for (bx, by, angle_offset, diverge_dir) in &branch_points {
            self.draw_branch(
                canvas,
                *bx,
                *by,
                *angle_offset + diverge_dir * 0.4,  // Bias branch angle toward divergence
                (plant_height as f32 * self.dna.branch_length) as i32,
                0,
            );
        }

        // Fill in central foliage between branches
        if self.dna.branch_count > 2 {
            self.draw_inner_foliage(canvas, center_x as i32, trunk_top, ground_y, &branch_points);
        }

        // If very few branches, add crown foliage at top
        if self.dna.branch_count <= 3 {
            self.draw_crown(canvas, center_x as i32, trunk_top);
        }
    }

    fn draw_inner_foliage(&mut self, canvas: &mut PlantCanvas, center_x: i32, top_y: i32, bottom_y: i32, branch_points: &[(f32, f32, f32, f32)]) {
        // Find the vertical range where branches exist
        let branch_ys: Vec<i32> = branch_points.iter().map(|(_, y, _, _)| *y as i32).collect();
        let min_branch_y = branch_ys.iter().min().copied().unwrap_or(top_y);
        let max_branch_y = branch_ys.iter().max().copied().unwrap_or(bottom_y);

        // Fill foliage - extend well above top, cut off earlier at bottom
        let foliage_top = top_y - 4;  // Start above the trunk top
        let foliage_bottom = min_branch_y + (max_branch_y - min_branch_y) / 2;  // Stop midway down branches

        for y in foliage_top..=foliage_bottom {
            // Width: starts small at top, grows, then tapers at bottom
            let progress = (y - foliage_top) as f32 / (foliage_bottom - foliage_top).max(1) as f32;
            let width_factor = if progress < 0.25 {
                0.5 + progress * 2.0  // Grow from top
            } else if progress > 0.75 {
                1.0 - (progress - 0.75) * 2.0  // Taper at bottom
            } else {
                1.0  // Full width in middle
            };
            let max_width = (self.dna.crown_spread * 14.0 * width_factor) as i32;

            for dx in -max_width..=max_width {
                let dist = dx.abs() as f32 / max_width.max(1) as f32;
                // Sparser in center, fills in gaps
                let center_factor = if dx.abs() < 3 { 0.4 } else { 1.0 };
                let prob = self.dna.leaf_density as f64 * (1.0 - dist as f64 * 0.4) * 0.5 * center_factor;

                if self.rng.gen_bool(prob.max(0.0)) {
                    let ch = if self.rng.gen_bool(0.82) {
                        self.dna.leaf_char
                    } else {
                        ['.', ',', '\'', '`'][self.rng.gen_range(0..4)]
                    };
                    canvas.set(center_x + dx, y, ch, self.dna.leaf_color);
                }
            }
        }
    }

    fn draw_pot(&mut self, canvas: &mut PlantCanvas, x: i32, y: i32) {
        let pot_width = (self.dna.trunk_thickness * 3.0) as i32 + 3;
        let half = pot_width / 2;

        canvas.set(x - half, y, '\\', Color::Rgb(139, 90, 43));
        for dx in (-half + 1)..half {
            canvas.set(x + dx, y, '_', Color::Rgb(139, 90, 43));
        }
        canvas.set(x + half, y, '/', Color::Rgb(139, 90, 43));
    }

    fn draw_stem(
        &mut self,
        canvas: &mut PlantCanvas,
        start_x: f32,
        start_y: f32,
        end_y: f32,
        stem_idx: u32,
        divergence_dir: f32,  // -1 to +1: direction to diverge as stem grows
    ) -> Vec<(f32, f32, f32, f32)> {  // (x, y, angle, diverge_dir)
        let mut branch_points = Vec::new();
        let height = start_y - end_y;
        let branch_zone_start = height * (1.0 - self.dna.branch_start);

        let mut x = start_x;
        let mut wobble: f32 = 0.0;

        // Divergence strength: how much stems spread apart at the top
        let divergence_strength = if self.dna.stem_count > 1 { 12.0 } else { 0.0 };

        // Different stem chars for different plant types
        let bark_chars = ['#', '%', '&', 'H', 'W'];
        let thin_bark = ['|', '!', 'l', 'I'];
        let grass_chars = ['|', '/', '\\', '(', ')'];

        // Waviness varies per stem for multi-stem plants
        let stem_wave_offset = stem_idx as f32 * 1.5;
        let is_grassy = self.dna.stem_count > 4 && self.dna.trunk_thickness < 0.2;

        for y_offset in 0..=(height as i32) {
            let y = start_y - y_offset as f32;
            let progress = y_offset as f32 / height;

            // Apply waviness (for vines, grass, etc.)
            let wave = if self.dna.waviness > 0.1 {
                ((y_offset as f32 * 0.25 + stem_wave_offset).sin() * self.dna.waviness * 3.0)
            } else {
                0.0
            };

            // Organic curve with wobble
            x += self.dna.trunk_curve * 0.08;
            wobble += self.rng.gen_range(-0.1..0.1);
            wobble *= 0.9;

            // Divergence: stems spread apart as they grow upward
            let divergence = divergence_dir * progress * divergence_strength;
            let effective_x = x + wobble + wave + divergence;

            // Thickness with slight variation
            let base_half_width = self.dna.trunk_thickness * 3.5;
            let taper_factor = 1.0 - progress * self.dna.trunk_taper;
            let noise = self.rng.gen_range(-0.2..0.2);
            let half_thick = ((base_half_width * taper_factor + noise).round() as i32).max(0);

            if half_thick == 0 {
                // Thin stem - use grass chars for grassy plants
                let ch = if is_grassy {
                    grass_chars[self.rng.gen_range(0..grass_chars.len())]
                } else {
                    thin_bark[self.rng.gen_range(0..thin_bark.len())]
                };
                let color = if is_grassy { self.dna.leaf_color } else { self.dna.trunk_color };
                canvas.set(effective_x as i32, y as i32, ch, color);
            } else {
                let left_edge = -half_thick + if self.rng.gen_bool(0.25) { 1 } else { 0 };
                let right_edge = half_thick - if self.rng.gen_bool(0.25) { 1 } else { 0 };

                for dx in left_edge..=right_edge {
                    let is_edge = dx == left_edge || dx == right_edge;
                    let ch = if is_edge {
                        if self.rng.gen_bool(0.8) { '|' } else { bark_chars[self.rng.gen_range(0..bark_chars.len())] }
                    } else {
                        bark_chars[self.rng.gen_range(0..bark_chars.len())]
                    };

                    let color_var: i16 = self.rng.gen_range(-15..15);
                    let trunk_color = if let Color::Rgb(r, g, b) = self.dna.trunk_color {
                        Color::Rgb(
                            (r as i16 + color_var).clamp(0, 255) as u8,
                            (g as i16 + color_var / 2).clamp(0, 255) as u8,
                            b,
                        )
                    } else {
                        self.dna.trunk_color
                    };

                    canvas.set(effective_x as i32 + dx, y as i32, ch, trunk_color);
                }
            }

            // Branch points
            if y_offset as f32 > branch_zone_start {
                let branch_probability = (progress - (1.0 - self.dna.branch_start))
                    / self.dna.branch_start
                    * (self.dna.branch_count as f32 / height);

                if self.rng.gen_bool((branch_probability * 0.3) as f64) {
                    let side = if self.rng.gen_bool(0.5) { -1.0 } else { 1.0 };
                    let angle = side * self.dna.branch_angle * self.rng.gen_range(0.7..1.3);
                    branch_points.push((effective_x, y, angle, divergence_dir));
                }
            }
        }

        // Grassy plants don't have branches - just a tip
        if is_grassy {
            // Add a seed head or leaf tip at top
            let tip_y = end_y as i32 - 1;
            let tip_char = if self.dna.has_flowers {
                self.dna.flower_char
            } else {
                ['*', 'Y', 'V', 'v', '"'][self.rng.gen_range(0..5)]
            };
            canvas.set(x as i32, tip_y, tip_char, self.dna.leaf_color);
            return branch_points; // No branches for grass
        }

        while branch_points.len() < self.dna.branch_count as usize {
            let progress = self.rng.gen_range(0.35..0.9);
            let y = start_y - height * progress;
            // Include divergence in branch starting position
            let divergence = divergence_dir * progress * divergence_strength;
            let bx = start_x + self.dna.trunk_curve * 0.1 * (progress * height) + divergence;
            let side = if branch_points.len() % 2 == 0 { 1.0 } else { -1.0 };
            let angle = side * self.dna.branch_angle * self.rng.gen_range(0.6..1.4);
            branch_points.push((bx, y, angle, divergence_dir));
        }

        branch_points.truncate(self.dna.branch_count as usize);
        branch_points
    }

    fn draw_branch(
        &mut self,
        canvas: &mut PlantCanvas,
        start_x: f32,
        start_y: f32,
        angle: f32,
        length: i32,
        depth: u32,
    ) {
        if length < 2 {
            return;
        }

        let mut x = start_x;
        let mut y = start_y;
        let mut current_angle = angle;

        for i in 0..length {
            let progress = i as f32 / length as f32;

            // Organic angle wobble
            current_angle += self.rng.gen_range(-0.08..0.08);

            let dx = current_angle.sin();
            let dy = -current_angle.cos().abs() * 0.7;

            // Droop accelerates toward end
            let droop = self.dna.branch_droop * progress * progress;

            x += dx + self.rng.gen_range(-0.05..0.05);
            y += dy + droop;

            // Branch character - / for going right, \ for going left
            let ch = if dx.abs() < 0.3 {
                '|'
            } else if dx > 0.0 {
                '/'
            } else {
                '\\'
            };

            let branch_color = if depth == 0 {
                // Slight color variation on main branches
                if let Color::Rgb(r, g, b) = self.dna.trunk_color {
                    let v: i16 = self.rng.gen_range(-10..10);
                    Color::Rgb((r as i16 + v).clamp(0, 255) as u8, g, b)
                } else {
                    self.dna.trunk_color
                }
            } else {
                self.dna.leaf_color
            };

            canvas.set(x as i32, y as i32, ch, branch_color);

            // Leaves along branch - dense foliage
            let leaf_chance = self.dna.leaf_density as f64 * 0.6 * (0.5 + progress as f64 * 0.5);
            if self.rng.gen_bool(leaf_chance) {
                self.draw_leaf(canvas, x as i32, y as i32, dx > 0.0);
                // Extra leaves for lush plants
                if self.dna.leaf_density > 0.6 && self.rng.gen_bool(0.4) {
                    self.draw_leaf(canvas, x as i32, y as i32 - 1, dx > 0.0);
                }
            }

            // Sub-branches
            if depth < self.dna.sub_branches && i > length / 4 && i < length * 3 / 4 {
                if self.rng.gen_bool(0.12) {
                    let angle_mult = self.rng.gen_range(0.4..0.8);
                    let sub_angle = if self.rng.gen_bool(0.5) {
                        current_angle + self.dna.branch_angle * angle_mult
                    } else {
                        current_angle - self.dna.branch_angle * angle_mult
                    };
                    let sub_length = (length as f32 * self.rng.gen_range(0.35..0.55)) as i32;
                    self.draw_branch(canvas, x, y, sub_angle, sub_length, depth + 1);
                }
            }
        }

        // End of branch
        if self.dna.has_flowers && self.rng.gen_bool(0.55) {
            canvas.set(x as i32, y as i32 - 1, self.dna.flower_char, self.dna.accent_color);
        } else if self.dna.has_fruit && self.rng.gen_bool(0.35) {
            canvas.set(x as i32, y as i32, self.dna.fruit_char, self.dna.accent_color);
        } else {
            self.draw_leaf_cluster(canvas, x as i32, y as i32);
        }
    }

    fn draw_leaf(&mut self, canvas: &mut PlantCanvas, x: i32, y: i32, right_side: bool) {
        let offset = if right_side { 1 } else { -1 };

        if self.dna.leaf_size > 0.5 {
            // Larger leaf - draw a small cluster
            canvas.set(x + offset, y, self.dna.leaf_char, self.dna.leaf_color);
            canvas.set(x + offset * 2, y, self.dna.leaf_char, self.dna.leaf_color);
            if self.dna.leaf_size > 0.7 {
                canvas.set(x + offset, y - 1, self.dna.leaf_char, self.dna.leaf_color);
                canvas.set(x + offset * 2, y - 1, '.', self.dna.leaf_color);
            }
        } else {
            // Small leaf
            canvas.set(x + offset, y, self.dna.leaf_char, self.dna.leaf_color);
            if self.rng.gen_bool(0.5) {
                let small_chars = ['.', ',', '\'', '`'];
                canvas.set(x + offset * 2, y, small_chars[self.rng.gen_range(0..4)], self.dna.leaf_color);
            }
        }
    }

    fn draw_leaf_cluster(&mut self, canvas: &mut PlantCanvas, x: i32, y: i32) {
        let size = (self.dna.crown_spread * 4.5) as i32 + 2;

        for dy in -size..=2 {
            let base_width = if self.dna.crown_shape < 0.3 {
                ((size * size - dy * dy).max(0) as f32).sqrt() as i32
            } else if self.dna.crown_shape > 0.7 {
                (size + dy).max(0)
            } else {
                size
            };

            // Slight width variation per row
            let width = base_width + self.rng.gen_range(-1..=1);

            for dx in -width..=width {
                let dist = dx.abs() as f32 / width.max(1) as f32;
                let prob = self.dna.leaf_density as f64 * (1.0 - dist as f64 * 0.4);

                if self.rng.gen_bool(prob.max(0.0)) {
                    let ch = if self.rng.gen_bool(0.82) {
                        self.dna.leaf_char
                    } else {
                        ['.', ',', '\'', '`'][self.rng.gen_range(0..4)]
                    };

                    canvas.set(x + dx, y + dy, ch, self.dna.leaf_color);
                }
            }
        }
    }

    fn draw_crown(&mut self, canvas: &mut PlantCanvas, x: i32, top_y: i32) {
        let crown_height = (self.dna.height * 14.0 * self.dna.crown_spread) as i32;
        let max_width = (self.dna.crown_spread * 11.0) as i32;

        let mut widths = Vec::new();

        for dy in 0..crown_height {
            let y = top_y - crown_height + dy;
            let progress = dy as f32 / crown_height as f32;

            let base_width = if self.dna.crown_shape < 0.3 {
                let r = crown_height as f32 / 2.0;
                let cy = dy as f32 - r;
                ((r * r - cy * cy).max(0.0).sqrt() * (max_width as f32 / r)) as i32
            } else if self.dna.crown_shape > 0.7 {
                ((1.0 - progress) * max_width as f32) as i32
            } else {
                if progress > 0.3 { max_width } else { (progress / 0.3 * max_width as f32) as i32 }
            };

            // Irregular edges
            let left = -base_width + self.rng.gen_range(-1..=1);
            let right = base_width + self.rng.gen_range(-1..=1);
            widths.push((left, right));

            for dx in left..=right {
                let dist = dx.abs() as f32 / base_width.max(1) as f32;
                let prob = self.dna.leaf_density as f64 * (1.0 - dist as f64 * 0.4);

                if self.rng.gen_bool(prob.max(0.0)) {
                    let ch = if self.rng.gen_bool(0.82) {
                        self.dna.leaf_char
                    } else {
                        ['.', ',', '`', '\''][self.rng.gen_range(0..4)]
                    };

                    canvas.set(x + dx, y, ch, self.dna.leaf_color);
                }
            }
        }

        // Scattered flowers/fruit
        if self.dna.has_flowers {
            let count = (crown_height as f32 * 0.3) as i32 + 2;
            for _ in 0..count {
                let fy = self.rng.gen_range(0..crown_height.max(1));
                let y = top_y - crown_height + fy;
                if let Some((l, r)) = widths.get(fy as usize) {
                    let fx = x + self.rng.gen_range(*l..=*r);
                    canvas.set(fx, y, self.dna.flower_char, self.dna.accent_color);
                }
            }
        }

        if self.dna.has_fruit {
            let count = (crown_height as f32 * 0.15) as i32 + 1;
            for _ in 0..count {
                let fy = self.rng.gen_range(crown_height / 2..crown_height.max(1));
                let y = top_y - crown_height + fy;
                if let Some((l, r)) = widths.get(fy as usize) {
                    let fx = x + self.rng.gen_range(*l..=*r);
                    canvas.set(fx, y, self.dna.fruit_char, self.dna.accent_color);
                }
            }
        }
    }
}

// ============================================================================
// MAIN APP
// ============================================================================

fn main() -> Result<()> {
    let fingerprint = SystemFingerprint::collect();
    let dna = PlantDna::from_fingerprint(&fingerprint);

    // Check for --info flag
    if std::env::args().any(|a| a == "--info") {
        println!("\n* Your system grows: {}", dna.describe());
        println!("  Machine: {}...", &fingerprint.machine_id[..12.min(fingerprint.machine_id.len())]);
        println!("  OS: {}", fingerprint.os);
        println!("  Distro: {}{}", fingerprint.distro,
            if fingerprint.distro_color.is_some() { " (has ANSI_COLOR)" } else { "" });
        println!("  Kernel: {}", fingerprint.kernel);
        println!("  Host: {}", fingerprint.hostname);
        println!("  User: {}", fingerprint.username);
        println!("  Arch: {}", fingerprint.arch);
        println!("  Base seed: {:016x}", fingerprint.base_seed());
        println!("\n  Parameters:");
        println!("    stem_count:     {}", dna.stem_count);
        println!("    growth_habit:   {:.2}", dna.growth_habit);
        println!("    height:         {:.2}", dna.height);
        println!("    base_spread:    {:.2}", dna.base_spread);
        println!("    waviness:       {:.2}", dna.waviness);
        println!("    trunk_thickness:{:.2}", dna.trunk_thickness);
        println!("    branch_count:   {}", dna.branch_count);
        println!("    leaf_density:   {:.2}", dna.leaf_density);
        println!("    has_flowers:    {}", dna.has_flowers);
        println!("    has_fruit:      {}", dna.has_fruit);
        println!();
        return Ok(());
    }

    // Setup terminal
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;

    loop {
        terminal.draw(|frame| {
            let area = frame.area();

            let plant_width = area.width.saturating_sub(4) as usize;
            let plant_height = area.height.saturating_sub(6) as usize;

            let mut canvas = PlantCanvas::new(plant_width.max(40), plant_height.max(20));
            let mut renderer = PlantRenderer::new(dna.clone(), fingerprint.base_seed());
            renderer.render(&mut canvas);

            let mut lines: Vec<Line> = Vec::new();
            for row in &canvas.cells {
                let spans: Vec<Span> = row
                    .iter()
                    .map(|(ch, color)| Span::styled(ch.to_string(), Style::default().fg(*color)))
                    .collect();
                lines.push(Line::from(spans));
            }

            let info = format!(
                " {} | {}@{} ",
                dna.describe(),
                fingerprint.username,
                fingerprint.hostname
            );

            let plant_widget = Paragraph::new(lines).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" sysplant ")
                    .title_bottom(Line::from(info).centered())
                    .border_style(Style::default().fg(Color::DarkGray)),
            );

            frame.render_widget(plant_widget, area);
        })?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press
                    && (key.code == KeyCode::Char('q') || key.code == KeyCode::Esc)
                {
                    break;
                }
            }
        }
    }

    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;

    println!("\n* Your system grows: {}", dna.describe());
    println!("  Seed: {:016x}\n", fingerprint.base_seed());

    Ok(())
}
