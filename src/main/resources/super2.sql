

SELECT * FROM user_account WHERE username= 'iotmining';
SELECT * FROM user_account WHERE username= 'dmg';

UPDATE user_account SET is_account_active =true where username= 'dmg';

SELECT * FROM tenants WHERE id = 'd728e3f7-8800-48c6-9a7a-056dbd54afdc';

SELECT * FROM role;

SELECT * FROM user_roles;


INSERT INTO user_roles(user_id, role_id) values('6b610682-7bf1-48a3-861e-9b1372ac9433', '33eb24bf-5328-4b50-9350-d78847a550e1');
