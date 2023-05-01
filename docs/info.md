### Secret

The App is the the most basic container. It has

1. An AccessKey, wich is a 32byte uuid, and

2. A data component witch is a Vec<u8>

The data is encrypt by using the Record's AccessKey and the parent Scope AccessKey

### Scope

The Scope is a container of Records. It has also

1. An AccessKey, wich is a 32byte uuid,

2. The scope data as a Vec<(String, Record)> where the String is the Record AccessKey as Base64;

### Profile

The profile contains user information and requirements for a particular entity that accesses the vault

1. The user's AccessKey witch may not be required as an authentication param,

2. The OS_UserId

3. The OS_UserName

4. The UserName

5. The UserPassword

6. The data as a HashMap<String, Scope> where the String is the **ScopeKeySecure**





### ### Concepts

1. SystemKey - A key created from some predefined well known properties of the system that will be used in every encryption method as an obfuscator.

2. AdminKey - A key created by deriving (Argon2) a password provided when the vault was created mixed with the SystemKey. Provides security for all the management functions.







