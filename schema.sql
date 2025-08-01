-- users table
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100),
  email VARCHAR(100) UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role VARCHAR(10) NOT NULL,
  semester INT,
  branch VARCHAR(50),
  roll_number VARCHAR(50)
);

-- subjects table
CREATE TABLE IF NOT EXISTS subjects (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  code VARCHAR(50) NOT NULL,
  semester VARCHAR(20),
  branch VARCHAR(50),
  faculty_id INT REFERENCES users(id) ON DELETE SET NULL
);

-- attendance table
CREATE TABLE IF NOT EXISTS attendance (
  id SERIAL PRIMARY KEY,
  student_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  subject_id INT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
  date DATE NOT NULL,
  hour INT NOT NULL,
  present BOOLEAN NOT NULL
);

-- whitelist table
CREATE TABLE IF NOT EXISTS whitelist (
  id SERIAL PRIMARY KEY,
  email VARCHAR(100) NOT NULL,
  role VARCHAR(10) NOT NULL CHECK(role IN ('student', 'faculty'))
);
