
SELECT * FROM role;

SELECT * FROM user_roles;
INSERT INTO user_roles(role_id, user_id) values(1, 1);
INSERT INTO user_roles(role_id, user_id) values(2, 1);
INSERT INTO user_roles(role_id, user_id) values(3, 1);

SELECT * FROM user_account;



UPDATE user_account SET is_account_active=true WHERE user_id=2;

INSERT INTO user_account(is_account_active, date_of_birth, email, first_name, gender, last_name, password, phone_number, username)
			values(true, '1997-04-16', 'santoshGndp@gmail.com', 'Santosh', 'Male', 'kumar', '$2a$12$FruU2eCLWiyubY9EEXqD3ODSnjFk/R7E.KqoByx./s830FC4O7OAS', 9874563210,'super');


ALTER TABLE dashboards
  ALTER COLUMN layouts SET DATA TYPE jsonb USING layouts::jsonb,
  ALTER COLUMN settings SET DATA TYPE jsonb USING settings::jsonb,
  ALTER COLUMN timewindow SET DATA TYPE jsonb USING timewindow::jsonb,
  ALTER COLUMN widgets SET DATA TYPE jsonb USING widgets::jsonb;
