package gf16

const (
	gfOrder = 65536
	gfPoly  = 0x1100B
)

var (
	GfExp [gfOrder]uint16
	GfLog [gfOrder]uint16
)

func init() {
	var val uint32 = 1
	for i := 0; i < gfOrder-1; i++ {
		GfExp[i] = uint16(val)
		GfLog[val] = uint16(i)
		val <<= 1
		if val >= gfOrder {
			val ^= gfPoly
		}
	}
	GfExp[gfOrder-1] = GfExp[0]
}

func Add(a, b uint16) uint16 {
	return a ^ b
}

func Sub(a, b uint16) uint16 {
	return a ^ b
}

func Mul(a, b uint16) uint16 {
	if a == 0 || b == 0 {
		return 0
	}
	logSum := int(GfLog[a]) + int(GfLog[b])
	if logSum >= gfOrder-1 {
		logSum -= gfOrder-1
	}
	return GfExp[logSum]
}

func Div(a, b uint16) uint16 {
	if a == 0 {
		return 0
	}
	if b == 0 {
		panic("division by zero in GF(2^16)")
	}
	logDiff := int(GfLog[a]) - int(GfLog[b])
	if logDiff < 0 {
		logDiff += gfOrder-1
	}
	return GfExp[logDiff]
}

func Pow(a uint16, n int) uint16 {
	if a == 0 {
		return 0
	}
	if n == 0 {
		return 1
	}
	logVal := (int(GfLog[a]) * n) % (gfOrder - 1)
	if logVal < 0 {
		logVal += gfOrder - 1
	}
	return GfExp[logVal]
}

func Inv(a uint16) uint16 {
	if a == 0 {
		panic("zero has no multiplicative inverse")
	}
	return GfExp[gfOrder-1-int(GfLog[a])]
}