# crypto

Read more [Elliptic Curve notes by Ben Lynn](https://web.archive.org/web/20220412170936/https://crypto.stanford.edu/pbc/notes/elliptic/)

Form : Y ^ 2 = X ^ 3 + a * X + b
The constants a,b must satisfy the relationship: 4a3 + 27 b2 ≠ 0

P(x1, y1), Q(x2, y2), R(x3, y3) are points in elliptic 

P + O = P
(P) + (-P) = 0
P + (Q + R) = (P + Q) + R
P + Q + R = R + P + Q

So what is point addition, it is a line, which intersecs Q, P and cut one point in elliptic.

What if we want to add two of the same point together: P + P? We can't draw a unique line through one point, but we can pick a unique line by calculating the tangent line to the curve at the point. Calculate the tangent line at the point P. Continue the line until it intersects with the curve at point R. 

Reflect this point as before: P + P = R' = R(x,-y).Sometimes you will pick two points P, Q and the line will not touch the curve again. In this case we say that the line intersects with the point (O) which is a single point located at the end of every vertical line at infinity. As such, point addition for an elliptic curve is defined in 2D space, with an additional point located at infinity.
