package main

import "errors"

type User struct {
	Id             string   `koanf:"Id"`
	Name           string   `koanf:"Name"`
	Password       string   `koanf:"Password"`
	IsAdmin        bool     `koanf:"IsAdmin"`
	AllowedDomains []string `koanf:"AllowedDomains"`
	ClearPassword  string
	Ip             string
}

// get user from configuration
func GetUserFromConfiguration(id string) (u *User) {
	if len(configuration.Users) == 0 {
		return nil
	}

	for _, u := range configuration.Users {
		if id == u.Id {
			return &u
		}
	}
	return nil
}

// check user against database and return real if exists
func (u *User) CustomValid() error {
	if u == nil {
		return errors.New("user: no user provided")
	}

	validUser := GetUserFromConfiguration(u.Id)
	if validUser == nil {
		return errors.New("user: not found")
	}

	if err := IsValidHash(u.ClearPassword, validUser.Password); err != nil {
		return errors.New("user: bad password\n\t-> " + err.Error())
	}

	u = validUser
	return nil
}

// return the matching user in configuration, or an error of not exists
func GetValidUserFromFormData(f *FormData) (u *User, err error) {
	u = &User{}
	if f == nil || !f.customValid {
		return nil, errors.New("user: bad formdata provided")
	}
	u.Id = f.Username
	u.Password = f.Password
	u.Ip = f.Ip

	// validate user
	return u, u.CustomValid()
}

// return a user from formData, no validation // NOT USED
func GetUserFromClaims(c *Claims) (u *User, err error) {
	u = &User{}
	if c == nil || !c.customValid {
		return nil, errors.New("user: bad claims provided")
	}
	u = GetUserFromConfiguration(c.Ip)
	if u == nil {
		return nil, errors.New("user: not found")
	}
	// do not validate user
	return u, nil
}
