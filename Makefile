.PHONY: create-role

create-role:
	aws iam create-role \
	--role-name rust-role \
	--assume-role-policy-document file://rust-role.json