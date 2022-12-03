# Websocket Server

A lightweight Websocket server library, written on top of BSD sockets API.


---
## API Documentation

### ***Utilities***

#### **Left Trim**

```c
char* string_ltrim(char* s);
```
Trim whitespace from the beginning of the string

- **param** s Pointer to string with whitespace
- **returns** Pointer to trimmed string, NULL if s is NULL

---

#### **Right Trim**

```c
char* string_rtrim(char* s);
```
Trim whitespace from the end of the string

- **param** s Pointer to string with whitespace
- **returns** Pointer to trimmed string, NULL if s is NULL

---

#### **Trim**

```c
char* string_trim(char* s);
```
Trim whitespace from the both ends of the string

- **param** s Pointer to string with whitespace
- **returns** Pointer to trimmed string, NULL if s is NULL
