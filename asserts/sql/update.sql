update auth_api
set name = concat('/auth', auth_api.name), url = concat('/auth', auth_api.url)
where 1 = 1;