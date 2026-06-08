package gf16

const (
	gfOrder = 65536
	gfPoly  = 0x1100B
)

var (
	gfExp [gfOrder]uint16
	gfLog [gfOrder]uint16
)

func init() {
	var val uint32 = 1
	for i := 0; i < gfOrder-1; i++ {
		gfExp[i] = uint16(val)
		gfLog[val] = uint16(i)
		val <<= 1
		if val >= gfOrder {
			val ^= gfPoly
		}
	}
	gfExp[gfOrder-1] = gfExp[0]
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
	logSum := int(gfLog[a]) + int(gfLog[b])
	if logSum >= gfOrder-1 {
		logSum -= gfOrder-1
	}
	return gfExp[logSum]
}

func Div(a, b uint16) uint16 {
	if a == 0 {
		return 0
	}
	if b == 0 {
		panic("division by zero in GF(2^16)")
	}
	logDiff := int(gfLog[a]) - int(gfLog[b])
	if logDiff < 0 {
		logDiff += gfOrder-1
	}
	return gfExp[logDiff]
}

func Pow(a uint16, n int) uint16 {
	if a == 0 {
		return 0
	}
	if n == 0 {
		return 1
	}
	logVal := (int(gfLog[a]) * n) % (gfOrder - 1)
	if logVal < 0 {
		logVal += gfOrder - 1
	}
	return gfExp[logVal]
}

func Inv(a uint16) uint16 {
	if a == 0 {
		panic("zero has no multiplicative inverse")
	}
	return gfExp[gfOrder-1-int(gfLog[a])]
}