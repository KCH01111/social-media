# 🧠 Tornado + Elasticsearch Social Media Backend (Minimal v1)

A **lean, production-style backend** for a social media app — built with **Tornado** and **Elasticsearch**.
This version focuses on **core user features** only: authentication and user profiles.

---

## 🚀 Current Status

* [x] User Registration with validation
* [x] Secure Login with JWT tokens
* [x] Password hashing with bcrypt
* [x] Token verification middleware
* [x] User profile CRUD (self + admin)
* [ ] Pagination & filtering on user listing
* [ ] Advanced search (later)

---

## ✅ Core Functional Areas (v1)

| Area        | Description                             | Status |
| ----------- | --------------------------------------- | ------ |
| **Auth**    | JWT login, password hashing, validation | ✅ Done |
| **Users**   | Profile view/update, admin management   | ✅ Done |
| **Routing** | Modular handlers                        | ✅ Done |

---

## 💾 Elasticsearch Data Modeling (v1)

**Indexes**:

* `users` – user profiles & credentials

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
│   ├── main.py              # Routing setup
│   ├── auth/
│   │   └── handlers.py      # Register/Login + JWT middleware
│   ├── users/
│   │   └── handlers.py      # Profile CRUD + admin tools
│   ├── services/
│   │   └── es.py            # Elasticsearch client
├── .env.example
├── README.md
├── requirements.txt
```

---

## 🔧 Quick Start

### 1️⃣ Install Dependencies

```bash
pip install tornado elasticsearch pyjwt bcrypt python-dotenv
```

### 2️⃣ Configure Environment

cp .env.example .env
# Edit:
# JWT_SECRET=your_secret
# ES_URL=http://localhost:9200
```

### 3️⃣ Run Elasticsearch (Docker)

docker run -d --name es -p 9200:9200 \
  -e "discovery.type=single-node" \
  docker.elastic.co/elasticsearch/elasticsearch:8.8.0
```

### 4️⃣ Create the Users Index

python scripts/create_users_index.py
```

### 5️⃣ Start Server

python app/main.py
```

---

## 📚 API Endpoints (v1)

### **Auth**

* `POST /auth/register` → create account
* `POST /auth/login` → login & get JWT

### **Users**

* `GET /users/me` → get own profile
* `PATCH /users/me` → update own profile
* `DELETE /users/me` → deactivate account
* `GET /users` → list users
* `GET /users/<username>` → view user
* `PATCH /admin/users/<username>` → admin update
* `DELETE /admin/users/<username>` → admin deactivate

---

## 🏗️ Design Notes

* **Small, clean codebase** to focus on learning
* **Stateless authentication** with JWT
* **Async Tornado** for scalability
* **Elasticsearch** for flexible search later

---

## 📄 License

MIT License

---
