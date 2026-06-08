package gf16

import "fmt"

type Matrix struct {
	Rows int
	Cols int
	Data []uint16
}

func NewMatrix(rows, cols int) *Matrix {
	return &Matrix{
		Rows: rows,
		Cols: cols,
		Data: make([]uint16, rows*cols),
	}
}

func (m *Matrix) Get(r, c int) uint16 {
	return m.Data[r*m.Cols+c]
}

func (m *Matrix) Set(r, c int, val uint16) {
	m.Data[r*m.Cols+c] = val
}

func (m *Matrix) Solve(b []uint16) error {
	if m.Rows != m.Cols {
		return fmt.Errorf("matrix must be square to solve system")
	}
	if len(b) != m.Rows {
		return fmt.Errorf("vector B dimension mismatch")
	}

	n := m.Rows
	for i := 0; i < n; i++ {
		pivotRow := i
		for r := i + 1; r < n; r++ {
			if m.Get(r, i) > m.Get(pivotRow, i) {
				pivotRow = r
			}
		}

		if m.Get(pivotRow, i) == 0 {
			return fmt.Errorf("matrix is singular and cannot be inverted")
		}

		if pivotRow != i {
			for c := i; c < n; c++ {
				v1, v2 := m.Get(i, c), m.Get(pivotRow, c)
				m.Set(i, c, v2)
				m.Set(pivotRow, c, v1)
			}
			b[i], b[pivotRow] = b[pivotRow], b[i]
		}

		pivot := m.Get(i, i)
		if pivot != 1 {
			invPivot := Inv(pivot)
			for c := i; c < n; c++ {
				m.Set(i, c, Mul(m.Get(i, c), invPivot))
			}
			b[i] = Mul(b[i], invPivot)
		}

		for r := 0; r < n; r++ {
			if r != i {
				factor := m.Get(r, i)
				if factor != 0 {
					for c := i; c < n; c++ {
						m.Set(r, c, Add(m.Get(r, c), Mul(factor, m.Get(i, c))))
					}
					b[r] = Add(b[r], Mul(factor, b[i]))
				}
			}
		}
	}

	return nil
}