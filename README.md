# Session 13 - Bai 6: User Context va phan quyen

Yeu cau JDK 21 va Docker. Chay `docker compose up -d --wait`, roi chay `./gradlew :identity-service:bootRun`, `./gradlew :product-service:bootRun`, `./gradlew :gateway-service:bootRun` o ba terminal. Identity cong 8080, Product 8081, Gateway 8888. Cac service dung cung `JWT_SECRET` va Gateway/Product dung cung `INTERNAL_HEADER_SECRET`. Gia tri mac dinh chi phuc vu demo, can thay khi trien khai.

Dang ky va dang nhap qua `http://localhost:8888/identity/api/auth/register` va `/login` voi JSON `{"username":"alice","password":"password123"}`. Lay `accessToken`, goi `GET http://localhost:8888/products/api/products` hoac `POST http://localhost:8888/products/api/products` voi header `Authorization: Bearer <token>` va body `{"name":"Laptop"}`. USER bi 403, ADMIN tra 200.

De tao ADMIN cho demo: dang ky user `admin`, sau do chay `docker compose exec postgres psql -U identity -d identity_db -c "UPDATE users SET role = 'ADMIN' WHERE username = 'admin';"` truoc khi dang nhap. Role khong duoc nhan tu form dang ky. Gateway xoa cac header X-User-* cua client, verify JWT roi them `X-User-Id`, `X-User-Role`, timestamp va chu ky HMAC. Product verify chu ky va timestamp truoc khi doc role; request truc tiep voi header gia mao bi 401. Danh sach product la du lieu demo trong memory, POST tra ket qua nhung khong luu DB.
