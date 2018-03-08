# passman
A Simple commandline password manager written in ruby

It encrypts the passwords with a masterkey and stores it in file for
easy acess. Store the file in your google drive folder for backup and to make it
accessible from any machine.

Each password entry has a username-password combination along with the
name and url for the service.

# Requirements
* ruby
* gem highline

# Usage
* ruby ./passman.rb add|get|delete|edit

* add an alias in your bash/zshrc file for easy access
i.e. alias passman="ruby path_to_passmanrb"
