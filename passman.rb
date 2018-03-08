require 'highline'
require 'openssl'
require 'pstore'

class EncryptedPStore < PStore
  attr_accessor :key

  def initialize(key, path, opts = {})
    @key = key
    super(path, opts)
  end

  private

  def dump(table)
    original = Marshal.dump(table)
    cipher = OpenSSL::Cipher::AES.new(256, :CBC).encrypt
    digest = OpenSSL::Digest::SHA256.new
    cipher_key = digest.digest key
    cipher.key = cipher_key
    cipher.update(original) + cipher.final
  end

  # decrypt
  def load(content)
    cipher = OpenSSL::Cipher::AES.new(256, :CBC).decrypt
    digest = OpenSSL::Digest::SHA256.new
    cipher_key = digest.digest key
    cipher.key = cipher_key

    dec_content = cipher.update(content) + cipher.final
    Marshal.load(dec_content)
  end
end

class PasswordManager
  attr_accessor :store, :cli

  def initialize
    @cli = HighLine.new
    if File.exist?(passwords_file_path)
      password = cli.ask("Key:  ") { |q| q.echo = false }
    else
      cli.say("Initializing new database at #{passwords_file_path}")
      cli.say("Don't forget your passphrase. It is unrecoverable")

      password = cli.ask("<%= @key %>: ") do |q|
        q.gather =  {
          "Enter your key" => "",
          "Now Confirm your key" => ""
        }
        q.verify_match = true
        q.echo = "*"
        q.responses[:mismatch] = "Passwords don't match. Try again."
      end

      cli.say("<%= color('Your password is: #{password}. Make sure you do not lose it. It is unrecoverable', :cyan, BOLD) %>")
    end
    @store = EncryptedPStore.new(password, passwords_file_path)
    store.transaction { cli.say("Total: #{store.roots.count} Entries") }
  rescue OpenSSL::Cipher::CipherError
    cli.say("<%= color('Passphrase does not match', :red) %>")
    initialize
  end

  def sendAction(action, *args)
    case action.to_s.to_sym
    when :get
      search_and_select(*args) do |entry|
        `echo #{entry[:password]} | pbcopy`
        cli.say("<%= color('Copied password for #{entry[:name]} to the clipboard', :green) %>")
      end
    when :add
      add_entry(*args)
    when :edit
      edit_entry(*args)
    when :delete
      delete_entry(*args)
    else
      cli.say("<%= color('Action #{action} not recognized', :red) %>")
    end
  end

  def delete_entry(*args)
    search_and_select(*args) do |entry|
      if cli.agree("Confirm Delete #{entry_string(entry)} ?", true)
        store.transaction do
          store.delete entry[:id]
        end

        cli.say("<%= color('#{entry[:name]} Deleted', :yellow) %>")
      else
        cli.say("<%= color('Cancelled Delete', :red) %>")
      end
    end
  end

  def edit_entry(*args)
    search_and_select(*args) do |entry|
      entry[:name] = cli.ask("Name: ") {|q| q.default = entry[:name] }.strip
      entry[:url] = cli.ask("Login Url: ") {|q| q.default = entry[:url] }.strip
      entry[:username] = cli.ask("Username: ") {|q| q.default = entry[:username] }.strip
      entry[:password] = cli.ask("Password: ") {|q| q.default = entry[:password] }.strip

      store.transaction do
        store[entry[:id]] = entry

        store.commit
      end
      cli.say("<%= color('#{entry[:name]} Updated', :green) %>")
    end
  end

  def add_entry(comma_separated_entry = nil)
    if comma_separated_entry
      name, url, username, password = comma_separated_entry.split(",").map(&:strip)
    else
      cli.say("Enter details to add")
      name = cli.ask("Name:  ").strip
      url = cli.ask("Login Url:  ").strip
      username = cli.ask("Username:  ").strip
      password = cli.ask("Password:  ").strip
    end

    if name.nil? || name.empty? || username.nil? || username.empty? || password.nil? || password.empty?
      return cli.say("Invalid Entry")
    end

    store.transaction do
      id = (store.roots.last || 0) + 1

      store[id] = {
        id: id,
        name: name,
        url: url,
        username: username,
        password: password
      }

      store.commit
    end

    cli.say("<%= color('#{name} Added', :green) %>")
  end

  def search_and_select(search_term = nil, &block)
    if search_term.nil?
      search_term = cli.ask("Search For: ")
    end

    valid_entries = []
    store.transaction do
      store.roots.each do |id|
        record = store[id]
        if [record[:name], record[:url], record[:username]].any? { |term| term =~ /.*#{search_term}.*/i }
          valid_entries << record
        end
      end
    end

    if valid_entries.length > 0
      cli.say("<%= color('Matched #{valid_entries.length} Entries', :yellow) %>")
      cli.choose do |menu|
        menu.prompt = "Choose an Entry: "

        valid_entries.sort_by {|e| e[:name] }.each do |entry|
          prompt = entry_string(entry)
          menu.choice(prompt) { yield entry }
        end

        menu.choice("Cancel") { cli.say("Goodbye") }
      end
    else
      cli.say("<%= color('No matching entries found', :yellow) %>")
    end
  end

  def entry_string(entry)
    "#{entry[:name]} - #{entry[:url]} - #{entry[:username]}"
  end

  def passwords_file_path
    return ENV['PASSMAN_DB'] if ENV['PASSMAN_DB']

    dir = if !Dir.exist?("#{Dir.home}/.passman") && Dir.exist?("#{Dir.home}/Google Drive")
      "#{Dir.home}/Google Drive"
    else
      "#{Dir.home}/.passman"
    end
    Dir.mkdir(dir) unless Dir.exist?(dir)
    "#{dir}/passman_store.pstore"
  end
end

pm = PasswordManager.new
action = ARGV[0]

pm.sendAction(action, *ARGV[1..-1])
