
SELECT * FROM role;

SELECT * FROM user_roles;

INSERT INTO user_roles(role_id, user_id) values('c9366e89-8eee-4d20-825e-fd81092e2634', 'f2b2f597-5b7d-4a74-80b8-2699b292bf5a');
INSERT INTO user_roles(role_id, user_id) values('33eb24bf-5328-4b50-9350-d78847a550e1', 'f2b2f597-5b7d-4a74-80b8-2699b292bf5a');
INSERT INTO user_roles(role_id, user_id) values('bf12ae53-a059-4dff-86d1-33cced2d1e18', 'f2b2f597-5b7d-4a74-80b8-2699b292bf5a');

SELECT * FROM user_account;



UPDATE user_account SET is_account_active=true WHERE user_id='f2c2f597-5b7d-4a74-80b8-2699b292bf5a';

INSERT INTO user_account(user_id, is_account_active, date_of_birth, email, first_name, gender, last_name, password, phone_number, username)
			values('f2b2f597-5b7d-4a74-80b8-2699b292bf5a', true, '1997-04-16', 'santoshGndp@gmail.com', 'Santosh', 'Male', 'kumar', '$2a$12$FruU2eCLWiyubY9EEXqD3ODSnjFk/R7E.KqoByx./s830FC4O7OAS', 9874563210,'super');


ALTER TABLE dashboards
  ALTER COLUMN layouts SET DATA TYPE jsonb USING layouts::jsonb,
  ALTER COLUMN settings SET DATA TYPE jsonb USING settings::jsonb,
  ALTER COLUMN timewindow SET DATA TYPE jsonb USING timewindow::jsonb,
  ALTER COLUMN widgets SET DATA TYPE jsonb USING widgets::jsonb;
