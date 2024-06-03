
"""

equal with return f1.resutant(f2, var)

it mean resultant f1 to f2 with variable var ??

"""


from sage.matrix.matrix2 import Matrix
def resultant(f1, f2, var):
    return Matrix.determinant(f1.sylvester_matrix(f2, var))
