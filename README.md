# 🧠 Tornado + Elasticsearch Social Media Backend (Minimal v1)

A **lean, production-style backend** for a social media app — built with **Tornado** and **Elasticsearch**.
This version focuses on **core user features**: authentication, user profiles, listing, and search.

---

## 🚀 Current Status

* [x] User Registration with validation
* [x] Secure Login with JWT tokens
* [x] Password hashing with bcrypt
* [x] Token verification middleware
* [x] User profile CRUD (self + admin)
* [x] **Unified pagination, filtering, and search on `/users`**
* [ ] Advanced search scoring & analytics (later)

---

## ✅ Core Functional Areas (v1)

| Area        | Description                                                | Status |
| ----------- | ---------------------------------------------------------- | ------ |
| **Auth**    | JWT login, password hashing, validation                    | ✅ Done |
| **Users**   | Profile view/update, admin management, list/search with ES | ✅ Done |
| **Routing** | Modular handlers                                           | ✅ Done |

---

## 💾 Elasticsearch Data Modeling (v1)

**Indexes**:

* `users` – user profiles, credentials, status, and metadata

---

## 🔑 Auth & Roles

* On **login**, a JWT token is issued with the user’s `sub` (username).
* Each request with `Authorization: Bearer <token>` is verified by the `@jwt_required` decorator.
* **Roles are not stored in the token**. They are always looked up in Elasticsearch for security.
* New users start with:

  ```json
  { "role": "user", "is_active": true }
  ```
* To promote a user to **admin**, update their ES document manually (or via future admin UI):

  ```bash
  curl -X POST "http://localhost:9200/users/_update/<username>" \
    -H 'Content-Type: application/json' \
    -d '{"doc": {"role": "admin"}}'
  ```
* Admin-only endpoints call `is_admin()`, which fetches the user from ES and enforces `role=admin`.

---

## 🛠️ Tech Stack

| Component      | Tool               |
| -------------- | ------------------ |
| **Backend**    | Tornado (async)    |
| **Auth**       | JWT, bcrypt        |
| **Database**   | Elasticsearch      |
| **Validation** | Manual in handlers |
| **Config**     | python-dotenv      |
| **Deployment** | Docker (optional)  |

---

## 📁 Folder Structure (v1)

```
social_media_backend/
├── app/
│   ├── main.py                # Routing setup
│   ├── auth/
│   │   └── handlers.py        # Register/Login + JWT middleware
│   ├── users/
│   │   └── handlers.py        # Profile CRUD + admin tools + unified list/search
│   ├── services/
│   │   └── es.py              # Elasticsearch client
│   ├── settings.py            # Config & constants
├── scripts/
│   └── create_users_index.py  # Create ES users index
├── .env.example
├── README.md
├── requirements.txt
```

---

## 🔧 Quick Start

### 1️⃣ Install Dependencies

pip install tornado elasticsearch pyjwt bcrypt python-dotenv


### 2️⃣ Configure Environment

cp .env.example .env
# Edit .env:
# JWT_SECRET=your_secret
# ES_URL=http://localhost:9200


### 3️⃣ Run Elasticsearch (Docker)

docker run -d --name es -p 9200:9200 \
  -e "discovery.type=single-node" \
docker.elastic.co/elasticsearch/elasticsearch:8.8.0
```

### 4️⃣ Create the Users Index

python scripts/create_users_index.py


### 5️⃣ Start Server

python app/main.py


---

## 📚 API Endpoints (v1)

### **Auth**

* `POST /auth/register` → create account
* `POST /auth/login` → login & get JWT

### **Users**

* `GET /users/me` → get own profile
* `PATCH /users/me` → update own profile
* `DELETE /users/me` → deactivate account
* `GET /users` → list or search users (pagination, active filter)
* `GET /users/<username>` → view user profile
* `PATCH /admin/users/<username>` → admin update
* `DELETE /admin/users/<username>` → admin deactivate

---

## 🏗️ Design Notes

* **Unified `/users` endpoint**:

  * Without `q` → list users
  * With `q` → search users (fuzzy, phrase prefix, scored)
* **Consistent pagination** across list & search
* **Stateless authentication** with JWT
* **Async Tornado** for scalability
* **Elasticsearch** for flexible search & filtering

---

## 📄 License

MIT License


