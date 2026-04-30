module Watchtower_EDR/server

go 1.25.5

require (
	Watchtower_EDR/shared v0.0.0
	github.com/blugelabs/bluge v0.2.2
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/uuid v1.6.0
	github.com/thanhpk/randstr v1.0.6
	golang.org/x/crypto v0.48.0
	golang.org/x/sys v0.43.0
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
	gopkg.in/yaml.v3 v3.0.1
	modernc.org/sqlite v1.45.0
)

require (
	github.com/RoaringBitmap/roaring v0.9.4 // indirect
	github.com/axiomhq/hyperloglog v0.0.0-20191112132149-a4c4c47bc57f // indirect
	github.com/bits-and-blooms/bitset v1.2.0 // indirect
	github.com/blevesearch/go-porterstemmer v1.0.3 // indirect
	github.com/blevesearch/mmap-go v1.0.4 // indirect
	github.com/blevesearch/segment v0.9.0 // indirect
	github.com/blevesearch/snowballstem v0.9.0 // indirect
	github.com/blevesearch/vellum v1.0.7 // indirect
	github.com/blugelabs/bluge_segment_api v0.2.0 // indirect
	github.com/blugelabs/ice v1.0.0 // indirect
	github.com/blugelabs/ice/v2 v2.0.1 // indirect
	github.com/caio/go-tdigest v3.1.0+incompatible // indirect
	github.com/dgryski/go-metro v0.0.0-20180109044635-280f6062b5bc // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/golang/snappy v0.0.1 // indirect
	github.com/klauspost/compress v1.15.2 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mschoch/smat v0.2.0 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/exp v0.0.0-20251023183803-a4bb9ffd2546 // indirect
	golang.org/x/text v0.34.0 // indirect
	modernc.org/libc v1.67.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

replace Watchtower_EDR/shared => ../shared
