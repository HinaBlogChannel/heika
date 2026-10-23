//! 畑。4×4 のタイルに、送金1件ごとに何かが1つ生える。何が生えるかは種（トランザクションのハッシュ）だけで決まる。
//! 珍しいものに優劣はつけない。自然科学は気にしない。

/// 1タイルの一辺（ドット）
const TILE: u32 = 48;
/// 畑の一辺（ドット）
pub const SIZE: u32 = TILE * 4;
/// 背の高い木が、いちばん上の段からはみ出す分
const SKY: u32 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Grass,
    Susuki,
    Foxtail,
    Clover,
    Fern,
    Moss,
    Horsetail,
    Birch,
    Yakusugi,
    Hinoki,
    Sunflower,
    Flytrap,
    Cactus,
    Mushroom,
    Bamboo,
    Tulip,
    Rafflesia,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Grass => "草",
            Kind::Susuki => "ススキ",
            Kind::Foxtail => "ねこじゃらし",
            Kind::Clover => "クローバー",
            Kind::Fern => "シダ",
            Kind::Moss => "コケ",
            Kind::Horsetail => "つくし",
            Kind::Birch => "白樺",
            Kind::Yakusugi => "屋久杉",
            Kind::Hinoki => "ヒノキ",
            Kind::Sunflower => "ひまわり",
            Kind::Flytrap => "ハエトリグサ",
            Kind::Cactus => "サボテン",
            Kind::Mushroom => "キノコ",
            Kind::Bamboo => "竹",
            Kind::Tulip => "チューリップ",
            Kind::Rafflesia => "ラフレシア",
        }
    }

    /// 種の1バイトで選ぶ。草不可避なので草の仲間が半分を超え、あとはだいたい同じくらい
    fn choose(byte: u8) -> Self {
        const TABLE: [(Kind, u16); 17] = [
            (Kind::Grass, 50),
            (Kind::Susuki, 15),
            (Kind::Foxtail, 15),
            (Kind::Clover, 15),
            (Kind::Fern, 15),
            (Kind::Moss, 15),
            (Kind::Horsetail, 15),
            (Kind::Birch, 12),
            (Kind::Yakusugi, 10),
            (Kind::Hinoki, 12),
            (Kind::Sunflower, 12),
            (Kind::Flytrap, 12),
            (Kind::Cactus, 12),
            (Kind::Mushroom, 12),
            (Kind::Bamboo, 12),
            (Kind::Tulip, 12),
            (Kind::Rafflesia, 10),
        ];
        let mut rest = byte as u16;
        for (kind, weight) in TABLE {
            if rest < weight {
                return kind;
            }
            rest -= weight;
        }
        Kind::Grass
    }

    /// ドット絵。下の行が地面に着く。`.` は透明
    fn sprite(self) -> &'static [&'static str] {
        match self {
            Kind::Grass => &[
                "......g....g....",
                "..g..gG...gG..g.",
                "..gG.gG.g.gG.gG.",
                ".gGg.gGggGgGgGg.",
                ".gGgGgGgGgGgGgG.",
            ],
            Kind::Susuki => &[
                "..e.....e...e...",
                "..ee...ee..ee...",
                "...e...e...e....",
                "...ee.ee..ee....",
                "....g.g...g.....",
                "....g.g..g......",
                "....gg.g.g......",
                ".....g.gg.......",
                "...g.gggg.g.....",
                "....gggggg......",
            ],
            Kind::Foxtail => &[
                "....ll......ll..",
                "...llll....lll..",
                "...lll....lll...",
                "....g....g......",
                "....g...g.......",
                ".....g.g...ll...",
                ".....g.g..lll...",
                "......gg.g......",
                "......ggg.......",
                ".....ggggg......",
            ],
            Kind::Clover => &[
                "..........w.....",
                ".........www....",
                ".GG.GG....w.....",
                "GGGGGGG...g.....",
                ".GGgGG....g.GG..",
                "..GGG.....gGGGG.",
                "...g.....g..GG..",
                "...g....g...g...",
                "....g..g...g....",
                ".....gg..gg.....",
            ],
            Kind::Fern => &[
                "..........g.....",
                ".........gGg....",
                "........gGgGg...",
                "...g...gGg.Gg...",
                "..gGg.gGg...g...",
                ".gGgGgGg........",
                "..gGgGg.........",
                "...gGg..........",
                "....gg..........",
                ".....gg.........",
            ],
            Kind::Moss => &[
                "....llll........",
                "..llGlllGl..ll..",
                ".lGllllGlllllGl.",
                "llllGllllGllllll",
            ],
            Kind::Horsetail => &[
                "..t.......t.....",
                ".ttt.....ttt....",
                ".ttt.....ttt....",
                "..t...t...t.....",
                "..T..ttt..T.....",
                "..t..ttt..t.....",
                "..T...t...T.....",
                "..t...T...t.....",
                "..t...t...t.....",
            ],
            Kind::Birch => &[
                ".....GGlGG......",
                "...GGlGGGlGG....",
                "..GlGGGlGGGlG...",
                ".GGGlGGGGlGGGG..",
                "..GGGGlGGGGlG...",
                "...GlGGwwlGG....",
                ".....GGwwG......",
                ".......ww.......",
                ".......wk.......",
                ".......ww.......",
                ".......kw.......",
                ".......ww.......",
                ".......wk.......",
                ".......ww.......",
                ".......kw.......",
                ".......ww.......",
                "......wwww......",
            ],
            Kind::Yakusugi => &[
                "....ggggggg.....",
                "..gggGgggGggg...",
                ".ggGgggggggGgg..",
                "gggggGgggGggggg.",
                ".ggGggggggggGgg.",
                "..gggggGggggg...",
                "...ggggggggg....",
                "..gggGgggGgggg..",
                ".gggggggggggggg.",
                "..ggggBBBgggg...",
                "......BBB.......",
                ".....BBbBB......",
                ".....BbBBB......",
                "....BBBBbBB.....",
                "....BbBBBBB.....",
                "...BBBBBbBBB....",
                "..BBbBBBBBBbB...",
                ".BB..BBBBB..BB..",
            ],
            Kind::Hinoki => &[
                ".......g........",
                "......ggg.......",
                "......gGg.......",
                ".....ggggg......",
                ".....gGggg......",
                "....ggggGgg.....",
                "....gGggggg.....",
                "...gggggGggg....",
                "...ggGgggggg....",
                "..gggggggGggg...",
                "..ggGgggggggg...",
                ".......h........",
                ".......h........",
                "......hhh.......",
            ],
            Kind::Sunflower => &[
                "......yyyy......",
                "....yyyyyyyy....",
                "...yyyBBBByyy...",
                "...yyBBBBBByy...",
                "...yyBBBBBByy...",
                "...yyyBBBByyy...",
                "....yyyyyyyy....",
                "......yyyy......",
                ".......gg.......",
                "...GG..gg.......",
                "....GGggg.......",
                ".......gg..GG...",
                ".......gggGG....",
                ".......gg.......",
                ".......gg.......",
            ],
            Kind::Flytrap => &[
                "..rr......rr....",
                ".grrg....grrg...",
                ".gwwg....gwwg...",
                ".grrg....grrg...",
                "..gg......gg....",
                "...g......g.....",
                "....g....g......",
                ".....g..g.......",
                "......gg........",
                ".....gggg.......",
            ],
            Kind::Cactus => &[
                ".......cc.......",
                "......cccc......",
                "......cpcc..cc..",
                "..cc..cccc..cc..",
                "..cc..ccpc..cc..",
                "..cc..cccccccc..",
                "..cccccccccc....",
                "......cccc......",
                "......cpcc......",
                "......cccc......",
            ],
            Kind::Mushroom => &[
                "....mmmmmm......",
                "...mmwmmmwmm....",
                "..mmmmmmmmmmm...",
                "..mwmmmwmmmwm...",
                ".....wwww.......",
                ".....wwww.......",
                ".....wwww.......",
            ],
            Kind::Bamboo => &[
                "....l.....l.....",
                "...lG....lG..l..",
                "...lG....Gl..Gl.",
                "...kk....kk..Gl.",
                "...lG....Gl..kk.",
                "...lG....Gl..Gl.",
                "...lG....kk..Gl.",
                "...kk....Gl..Gl.",
                "...lG....Gl..kk.",
                "...lG....Gl..Gl.",
                "...lG....kk..Gl.",
                "...kk....Gl..Gl.",
                "...lG....Gl..Gl.",
            ],
            Kind::Tulip => &[
                "......r.r.......",
                ".....rrrrr......",
                ".....rrrrr......",
                "......rrr.......",
                ".......g........",
                ".....G.g.G......",
                "......Ggg.......",
                ".......g........",
            ],
            Kind::Rafflesia => &[
                "....rrr..rrr....",
                "...rwrr..rrwr...",
                "..rrrrrkkrrrrr..",
                "..rrrrkkkkrrrr..",
                "...rwrrkkrrwr...",
                "....rrr..rrr....",
            ],
        }
    }
}

fn color(code: u8) -> Option<&'static str> {
    Some(match code {
        b'g' => "#2e7d32",
        b'G' => "#66bb6a",
        b'l' => "#9ccc65",
        b'w' => "#f2f2ec",
        b'k' => "#3e3e3e",
        b'B' => "#5d4037",
        b'b' => "#3e2723",
        b'h' => "#a1553a",
        b'y' => "#fdd835",
        b'r' => "#d32f2f",
        b'p' => "#f8bbd0",
        b'c' => "#43a047",
        b'm' => "#e53935",
        b'e' => "#e8dcc0",
        b't' => "#c8a165",
        b'T' => "#8d6e3f",
        _ => return None,
    })
}

/// 生えた1つ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plant {
    pub kind: Kind,
    /// 左端（ドット）
    x: u32,
    /// 地面に着く下端（ドット）
    ground: u32,
    flip: bool,
    /// まだ確定していない送金で生えたもの。薄く描く
    pub growing: bool,
}

impl Plant {
    pub fn new(seed: &[u8; 32], growing: bool) -> Self {
        let tile = (seed[0] & 15) as u32;
        let (column, row) = (tile % 4, tile / 4);
        Self {
            kind: Kind::choose(seed[1]),
            x: column * TILE + seed[2] as u32 % (TILE - 15),
            ground: row * TILE + 16 + seed[3] as u32 % (TILE - 15),
            flip: seed[4] & 1 == 1,
            growing,
        }
    }
}

/// 畑の SVG。ドットは横に続く同じ色をまとめて1つの rect にする
pub fn svg(plants: &[Plant]) -> String {
    let height = SIZE + SKY;
    let mut out = format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{SIZE}" height="{height}" viewBox="0 -{SKY} {SIZE} {height}" shape-rendering="crispEdges">"#
    );
    out.push_str(&format!(
        r##"<rect x="0" y="-{SKY}" width="{SIZE}" height="{SKY}" fill="#dff1fb"/>"##
    ));
    for tile in 0..16 {
        let (column, row) = (tile % 4, tile / 4);
        let fill = if (column + row) % 2 == 0 {
            "#8d6e63"
        } else {
            "#7b5d52"
        };
        out.push_str(&format!(
            r#"<rect x="{}" y="{}" width="{TILE}" height="{TILE}" fill="{fill}"/>"#,
            column * TILE,
            row * TILE
        ));
        // 土の粒。どの畑でも同じ
        for speck in 0..5u32 {
            let value =
                (tile * 7 + speck * 13 + 1).wrapping_mul(2654435761u32.wrapping_mul(speck + 1));
            out.push_str(&format!(
                r##"<rect x="{}" y="{}" width="2" height="1" fill="#6d4c41"/>"##,
                column * TILE + 3 + value % (TILE - 6),
                row * TILE + 3 + (value >> 8) % (TILE - 6)
            ));
        }
    }
    let mut order: Vec<&Plant> = plants.iter().collect();
    order.sort_by_key(|plant| (plant.ground, plant.x));
    for plant in order {
        let sprite = plant.kind.sprite();
        // 背の高い木は、いちばん上の段で空（負の y）にはみ出す
        let top = plant.ground as i64 - sprite.len() as i64;
        if plant.growing {
            out.push_str(r#"<g opacity="0.45">"#);
        }
        for (dy, line) in sprite.iter().enumerate() {
            let bytes: Vec<u8> = if plant.flip {
                line.bytes().rev().collect()
            } else {
                line.bytes().collect()
            };
            let mut start = 0;
            while start < bytes.len() {
                let mut end = start + 1;
                while end < bytes.len() && bytes[end] == bytes[start] {
                    end += 1;
                }
                if let Some(fill) = color(bytes[start]) {
                    out.push_str(&format!(
                        r#"<rect x="{}" y="{}" width="{}" height="1" fill="{fill}"/>"#,
                        plant.x + start as u32,
                        top + dy as i64,
                        end - start
                    ));
                }
                start = end;
            }
        }
        if plant.growing {
            out.push_str("</g>");
        }
    }
    out.push_str("</svg>");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Kind; 17] = [
        Kind::Grass,
        Kind::Susuki,
        Kind::Foxtail,
        Kind::Clover,
        Kind::Fern,
        Kind::Moss,
        Kind::Horsetail,
        Kind::Birch,
        Kind::Yakusugi,
        Kind::Hinoki,
        Kind::Sunflower,
        Kind::Flytrap,
        Kind::Cactus,
        Kind::Mushroom,
        Kind::Bamboo,
        Kind::Tulip,
        Kind::Rafflesia,
    ];

    #[test]
    fn sprites_are_16_wide_with_known_colors() {
        for kind in ALL {
            for line in kind.sprite() {
                assert_eq!(line.len(), 16, "{}: {line}", kind.name());
                for code in line.bytes() {
                    assert!(
                        code == b'.' || color(code).is_some(),
                        "{}: {}",
                        kind.name(),
                        code as char
                    );
                }
            }
            assert!(
                kind.sprite().len() as u32 <= 16 + SKY,
                "{} は空にはみ出す",
                kind.name()
            );
        }
    }

    #[test]
    fn every_byte_chooses_something_and_all_kinds_appear() {
        let chosen: Vec<Kind> = (0..=255u8).map(Kind::choose).collect();
        for kind in ALL {
            assert!(chosen.contains(&kind), "{} が出ない", kind.name());
        }
        assert_eq!(chosen.iter().filter(|k| **k == Kind::Grass).count(), 50);
    }

    #[test]
    fn plants_stay_inside_the_field() {
        for byte in 0..=255u8 {
            let plant = Plant::new(&[byte; 32], false);
            assert!(plant.x + 16 <= SIZE);
            assert!(plant.ground <= SIZE);
            assert!(plant.ground as i64 - plant.kind.sprite().len() as i64 >= -(SKY as i64));
        }
    }

    #[test]
    fn same_seeds_draw_the_same_field() {
        let plants: Vec<Plant> = (0..40u8)
            .map(|i| Plant::new(&[i.wrapping_mul(37); 32], i % 7 == 0))
            .collect();
        assert_eq!(svg(&plants), svg(&plants.clone()));
        assert!(svg(&plants).contains(r#"opacity="0.45""#));
    }
}
