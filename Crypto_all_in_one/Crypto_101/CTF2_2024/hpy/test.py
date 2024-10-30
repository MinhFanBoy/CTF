from typing import Tuple

class FiniteField:
    def __init__(self, p: int):
        self.p = p
    
    def add(self, a: int, b: int) -> int:
        return (a + b) % self.p
    
    def sub(self, a: int, b: int) -> int:
        return (a - b) % self.p
    
    def mul(self, a: int, b: int) -> int:
        return (a * b) % self.p
    
    def inv(self, a: int) -> int:
        if a == 0:
            raise ValueError("Zero has no inverse in finite field")
        return pow(a, self.p - 2, self.p)
    
    def div(self, a: int, b: int) -> int:
        return self.mul(a, self.inv(b))

def compute_curve_parameters(a: int, d: int, omega: int, q: int, p: int) -> Tuple[int, int, int]:
    """
    Tính các tham số của đường cong Weierstrass twist
    A = 2(a+d)/(a-d)
    B = 4/(a-d)
    b = (3-A^2)/(3B^2)
    c = (2A^3-9A)/(27B^3)
    """
    F = FiniteField(p)
    
    # Tính A và B
    numerator = F.mul(2, F.add(a, d))
    denominator = F.sub(a, d)
    A = F.div(numerator, denominator)
    
    B = F.div(4, denominator)
    
    # Tính b và c theo công thức (13)
    A_squared = F.mul(A, A)
    B_squared = F.mul(B, B)
    B_cubed = F.mul(B_squared, B)
    
    # b = (3-A^2)/(3B^2)
    t1 = F.sub(3, A_squared)
    t2 = F.mul(3, B_squared)
    b = F.div(t1, t2)
    
    # c = (2A^3-9A)/(27B^3)
    A_cubed = F.mul(A_squared, A)
    t3 = F.sub(F.mul(2, A_cubed), F.mul(9, A))
    t4 = F.mul(27, B_cubed)
    c = F.div(t3, t4)
    
    return A, b, c

def edwards_to_weierstrass_twist(x: int, y: int, a: int, d: int, omega: int, p: int) -> Tuple[int, int]:
    """
    Chuyển đổi điểm từ Edwards sang Weierstrass twist theo công thức (14):
    ψ: (x,y) ↦ ((1+y)/B(1-y) + Aω^2/3B, ω^3(1+y)/Bx(1-y))
    """
    F = FiniteField(p)
    
    # Tính A và B
    numerator = F.mul(2, F.add(a, d))
    denominator = F.sub(a, d)
    A = F.div(numerator, denominator)
    B = F.div(4, denominator)
    
    # Tính (1+y)/(1-y)
    one_plus_y = F.add(1, y)
    one_minus_y = F.sub(1, y)
    t1 = F.div(one_plus_y, one_minus_y)
    
    # Tính Aω^2/3B
    omega_squared = F.mul(omega, omega)
    t2 = F.div(F.mul(A, omega_squared), F.mul(3, B))
    
    # X = (1+y)/B(1-y) + Aω^2/3B
    x_w = F.add(F.div(t1, B), t2)
    
    # Y = ω^3(1+y)/Bx(1-y)
    omega_cubed = F.mul(omega_squared, omega)
    y_w = F.div(F.mul(omega_cubed, one_plus_y), F.mul(F.mul(B, x), one_minus_y))
    
    return x_w, y_w

def verify_edwards_point(x: int, y: int, a: int, d: int, p: int) -> bool:
    """Kiểm tra điểm có thỏa mãn phương trình Edwards: ax^2 + y^2 = 1 + dx^2y^2"""
    F = FiniteField(p)
    left = F.add(F.mul(a, F.mul(x, x)), F.mul(y, y))
    right = F.add(1, F.mul(d, F.mul(F.mul(x, x), F.mul(y, y))))
    return left == right

def verify_weierstrass_twist(x: int, y: int, b: int, c: int, p: int) -> bool:
    """Kiểm tra điểm có thỏa mãn phương trình Weierstrass twist: v^2 = u^3 + bω^4u + cω^6"""
    F = FiniteField(p)
    left = F.mul(y, y)
    u_squared = F.mul(x, x)
    u_cubed = F.mul(u_squared, x)
    right = F.add(u_cubed, F.add(F.mul(b, x), c))
    return left == right

def example_with_twist():
    # Ví dụ với các tham số cụ thể
    p = 31  # Trường hữu hạn F_p
    q = 4   # Bậc của twist
    a = 2   # Tham số đường cong Edwards
    d = 3
    omega = 5  # Phần tử sinh của F_q
    
    print(f"\nChuyển đổi trên trường F_{p}:")
    print(f"Đường cong Edwards: {a}x^2 + y^2 = 1 + {d}x^2y^2")
    
    # Tính các tham số của đường cong Weierstrass twist
    A, b, c = compute_curve_parameters(a, d, omega, q, p)
    print(f"Tham số đường cong Weierstrass twist:")
    print(f"A = {A}, b = {b}, c = {c}")
    
    # Thử nghiệm với một điểm trên đường cong Edwards
    test_points = [
        (2, 4),
        (3, 5),
        (4, 7)
    ]
    
    for x_e, y_e in test_points:
        if verify_edwards_point(x_e, y_e, a, d, p):
            print(f"\nĐiểm Edwards ({x_e}, {y_e}) thỏa mãn đường cong Edwards")
            try:
                x_w, y_w = edwards_to_weierstrass_twist(x_e, y_e, a, d, omega, p)
                print(f"Chuyển đổi sang điểm Weierstrass twist: ({x_w}, {y_w})")
                
                if verify_weierstrass_twist(x_w, y_w, b, c, p):
                    print("Điểm thỏa mãn phương trình Weierstrass twist!")
                else:
                    print("Điểm KHÔNG thỏa mãn phương trình Weierstrass twist!")
                
            except ValueError as e:
                print(f"Lỗi khi chuyển đổi: {e}")
        else:
            print(f"\nĐiểm ({x_e}, {y_e}) KHÔNG thỏa mãn đường cong Edwards")

if __name__ == "__main__":
    example_with_twist()