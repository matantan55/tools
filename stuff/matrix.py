from __future__ import annotations
from itertools import product


class Matrix:
    def __init__(self, tdl: list[list]) -> None:
        if any(len(i) != len(tdl) for i in tdl):
            raise ValueError("the matrix must be a squared matrix")
        self.matrix = tdl

    def __getitem__(self, indexes: tuple[int, int] | int | list[int]) -> int | list:
        if type(indexes) == tuple:
            return self.matrix[indexes[0]][indexes[1]]
        if type(indexes) == int:
            return self.matrix[indexes]
        return [i[indexes[0]] for i in self.matrix]

    def __len__(self) -> int:
        return len(self.matrix)

    def __add__(self, other: Matrix | int | float) -> Matrix:
        if len(other) != len(self.matrix):
            raise ValueError("matrices must be the same size")
        if type(other) == Matrix:
            for i, j in product(range(len(self.matrix)), range(len(self.matrix))):
                self.matrix[i][j] += other[i, j]
        else:
            for i, j in product(range(len(self.matrix)), range(len(self.matrix))):
                self.matrix[i][j] += other
        return self

    def __sub__(self, other: Matrix | int | float) -> Matrix:
        if len(other) != len(self.matrix):
            raise ValueError("matrices must be the same size")
        if type(other) == Matrix:
            for i, j in product(range(len(self.matrix)), range(len(self.matrix))):
                self.matrix[i][j] -= other[i, j]
        else:
            for i, j in product(range(len(self.matrix)), range(len(self.matrix))):
                self.matrix[i][j] -= other
        return self

    def __xor__(self, other: Matrix) -> Matrix:
        if len(other) != len(self.matrix):
            raise ValueError("matrices must be the same size")
        for i, j in product(range(len(self.matrix)), range(len(self.matrix))):
            self.matrix[i][j] ^= other[i, j]
        return self

    def __str__(self) -> str:
        return "\n".join([f'| {" ".join(list(map(str, i)))} |' for i in self.matrix])

    def __mul__(self, other) -> Matrix:
        res = [[0 for _ in range(len(self.matrix))] for _ in range(len(self.matrix))]
        # explicit for loops
        for i, j, k in product(range(len(self.matrix)), range(len(other[0])), range(len(other))):
            # resulted matrix
            res[i][j] += self.matrix[i][k] * other[k][j]
        self.matrix = res
        return self


def main() -> None:
    matrix1 = [[1, 2, 3],
               [3, 4, 5],
               [7, 6, 4]]
    matrix2 = [[5, 2, 6],
               [5, 6, 7],
               [7, 6, 4]]
    print(Matrix(matrix1) * Matrix(matrix2))


if __name__ == "__main__":
    main()
