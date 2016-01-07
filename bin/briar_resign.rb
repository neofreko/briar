#!/usr/bin/env ruby

require 'fileutils'
require 'CFPropertyList'
require 'rexml/document'
require 'tmpdir'
require 'find'
require 'open3'
require 'briar/environment'
require 'dotenv'
require 'nokogiri-plist'

def msg(title, &block)
  puts "\n" + '-' * 10 + title + '-' * 10
  block.call
  puts '-' * 10 + '-------' + '-' * 10 + "\n"
end

def get_entlist_from_binary(path)
  system('brew update && brew install ldid') unless system('which ldid 1&2> /dev/null')
  output = []
  xml_header_found = 0
  Open3.popen3("ldid -e '#{path}'") do |_, stdout, _stderr, _wait_thr|
    out = stdout.read.strip
    xml_header_found += 1 if "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" == out
    output << out if xml_header_found < 2 && out
  end
  flat_output = output.join("\n")
  flat_output.strip!
  puts "#{path}\n #{flat_output}"
  flat_output == '' ? nil : Nokogiri::PList(flat_output)
end

def create_entlist(ios_entitlements_path, plist_xml_content)
  File.open(ios_entitlements_path, 'w+') do |file|
    file.puts '<?xml version="1.0" encoding="UTF-8"?>'
    file.puts '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"' \
              '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
    file.puts '<plist version="1.0">'
    file.puts plist_xml_content
    file.puts '</plist>'
  end
end

def update_wildcard(original, wildcard)
  bundles = original.split('.')

  if bundles[0].length == 10 && bundles[0].hex > 0
    bundles[0] = wildcard
    original = bundles.join('.')
  end

  original
end

def update_entlist(plist, wildcard, entitlements_to_remove)
  msg('INFO') do
    puts 'INFO: Original plist'
    puts plist
  end

  plist['application-identifier'] = \
    update_wildcard(plist['application-identifier'], wildcard) \
    if plist['application-identifier']

  plist['com.apple.developer.team-identifier'] = \
    update_wildcard(plist['com.apple.developer.team-identifier'], wildcard) \
    if plist['com.apple.developer.team-identifier']

  if plist['keychain-access-groups']
    new_keychains = []
    plist['keychain-access-groups'].each do |keychain|
      new_keychains << update_wildcard(keychain, wildcard)
    end

    plist['keychain-access-groups'] = new_keychains
  end

  plist['get-task-allow'] = true

  # remove aps-environment from entitlements
  # puts "entitlements_to_remove: #{entitlements_to_remove}"
  plist.delete_if { |key, _value| entitlements_to_remove.include? key }

  msg('INFO') do
    puts 'Updated plist'
    puts plist
  end

  plist
end

def briar_resign(opts)
  Dotenv.load

  puts "opts: #{opts}"

  ipa = opts[:ipa]
  unless ipa.end_with?('.ipa')
    msg('Error') do
      puts 'first arg must be an ipa'
    end
    exit 1
  end

  unless File.exist? ipa
    msg('Error') do
      puts ".ipa must exist at path '#{ipa}'"
    end
    exit 1
  end

  mobile_prov = opts[:profile]
  unless mobile_prov.end_with?('.mobileprovision')
    msg('Error') do
      puts 'second arg must be a path to a mobileprovision'
    end
    exit 1
  end

  unless File.exist? mobile_prov
    msg('Error') do
      puts "'#{mobile_prov}' must exist at path"
    end
    exit 1
  end

  wildcard = opts[:new_bundle_identifier]

  unless wildcard.length == 10
    msg 'error' do
      puts "'#{wildcard}' must have 10 characters eg 'RWTD8QPG2C'"
    end
    exit 1
  end

  unless system("grep #{wildcard} #{mobile_prov}")
    msg 'error' do
      puts "could not find wildcard '#{wildcard}' in '#{mobile_prov}'"
    end
    exit 1
  end

  signing_id = opts[:signing_identity]
  msg ('Info') do
    puts "will resign with identity '#{signing_id}'"
  end

  options = { ipa: ipa,
              provision: mobile_prov,
              id: signing_id,
              wildcard: wildcard,
              entitlements_to_remove: opts[:entitlements_to_remove]
            }

  # TODO: display entitlements discrepancy between current app and provided
  # mobileprovisioning profile

  resign_ipa(options)
end

def resign_ipa(options)
  work_dir = 'resigned'
  ipa = File.join(work_dir, File.basename(options[:ipa]))
  mp = File.join(work_dir, File.basename(options[:provision]))
  wildcard = options[:wildcard]
  entitlements_to_remove = options[:entitlements_to_remove]

  puts options

  puts 'INFO: making a directory to put the resigned ipa in'
  if File.exist? work_dir
    puts "INFO: found an existing work directory at '#{work_dir}' - removing it"
    unless system("rm -rf #{work_dir}")
      msg 'Error' do
        puts "could not remove existing work dir '#{work_dir}'"
      end
      exit 1
    end
  end

  unless system("mkdir #{work_dir}")
    msg 'Error' do
      puts "could not create a work directory '#{work_dir}'"
    end
    exit 1
  end

  puts "INFO: copying assets to '#{work_dir}'"
  unless system("cp #{options[:ipa]} #{ipa}")
    msg 'Error' do
      puts "could not copy '#{options[:ipa]}' to '#{ipa}'"
    end
    exit 1
  end

  unless system("cp #{options[:provision]} #{mp}")
    msg 'Error' do
      puts "could not copy #{options[:provision]} to #{mp}"
    end
    exit 1
  end

  puts "unzipping '#{ipa}'"
  unless system("unzip -qq #{ipa} -d #{work_dir}")
    msg ('Error') do
      puts "could not unzip -qq #{ipa} to '#{work_dir}'"
    end
    exit 1
  end

  payload_dir = "#{work_dir}/Payload"
  unless File.directory?(payload_dir)
    msg 'error' do
      puts "Did not find a 'Payload' directory inside .ipa"
    end
    exit 1
  end

  app_path = Dir.foreach(payload_dir).find { |x| /.*\.app/.match(x) }

  abs_app_path = "#{payload_dir}/#{app_path}"
  puts "INFO: found app at '#{abs_app_path}'"

  info_plist = Dir.foreach(abs_app_path).find { |x| /^Info\.plist$/.match(x) }

  if info_plist.nil?
    msg 'error' do
      puts 'could not find an *-Info.plist file'
    end
    exit 1
  end

  info_plist_path = "#{abs_app_path}/#{info_plist}"
  puts "INFO: found info plist at '#{info_plist_path}'"

  mp_id = File.basename(mp, '.mobileprovision')
  puts "INFO: found mobile provision id '#{mp_id}'"

  puts "INFO: replacing embedded.mobileprovision with '#{mp}'"

  unless system("cp \"#{mp}\" \"#{abs_app_path}/embedded.mobileprovision\"")
    msg 'error' do
      puts "could not cp '#{mp}' to '#{abs_app_path}/embedded.mobileprovision'"
    end
    exit 1
  end

  plist = CFPropertyList::List.new(file: info_plist_path)
  data = CFPropertyList.native_types(plist.value)

  if data.nil? || !data.is_a?(Hash)
    msg 'error' do
      puts "Unable to parse binary plist: #{info_plist_path}"
    end
  end

  puts "INFO: parsed plist at '#{info_plist_path}'"

  bundle_identifier = options[:bundle_identifier] ? options[:bundle_identifier] : data['CFBundleIdentifier']

  Dir.glob("#{abs_app_path}/**/*.xcent").each do |existing_xcent|
    puts "INFO: Updating the existing: '#{existing_xcent}'"
    plist = Nokogiri::PList(open(existing_xcent))
    updated_plist = update_entlist(plist, wildcard, entitlements_to_remove)
    puts "Updated *.xcent plist: #{updated_plist.to_plist_xml(2)}"
    create_entlist(existing_xcent, updated_plist.to_plist_xml(2))
  end

  unless bundle_identifier
    msg 'error' do
      puts "Unable to find CFBundleIdentifier in plist '#{data}'"
    end
    exit 1
  end

  puts "INFO: found bundle identifier '#{bundle_identifier}'"
  # Save changes to plist
  unless data['CFBundleIdentifier'] == bundle_identifier
    puts "INFO: saving the new bundle identifier '#{bundle_identifier}' to plist file"
    data['CFBundleIdentifier'] = bundle_identifier
    plist.value = CFPropertyList.guess(data)
    plist.save(info_plist_path, CFPropertyList::List::FORMAT_XML)
  end

  bundle_exec = data['CFBundleExecutable']

  unless bundle_exec
    msg 'error' do
      puts "unable to find CFBundleExecutable in plist '#{data}'"
    end
    exit 1
  end

  puts "INFO: found bundle executable '#{bundle_exec}'"

  appname = app_path.split('.app')[0]

  puts "INFO: found appname '#{appname}'"

  Dir.glob("#{abs_app_path}/**/*").each do |file|
    next if File.directory?(file)
    cmd = "xcrun otool -h \"#{file}\""
    Open3.popen3(cmd) do |_, stderr, _, _|
      err = stderr.read.strip
      unless err[/is not an object file/, 0]
        puts "INFO: creating new entitlements with '#{wildcard}'"

        ios_entitlements_path = File.join(work_dir, "#{Time.now.to_f}-new-entitlements.plist")
        plist = get_entlist_from_binary(file)
        puts "original plist #{file}: #{plist}"
        if !plist.nil?
          plist['get-task-allow'] = true
        else
          plist = Nokogiri::PList({ 'get-task-allow' => true }.to_plist_xml)
        end

        updated_plist = update_entlist(plist, wildcard, entitlements_to_remove)
        puts "updated plist #{file}: #{updated_plist.to_plist_xml(2)}"
        create_entlist(ios_entitlements_path, updated_plist.to_plist_xml(2))

        identifier = updated_plist['application-identifier']
        identifier = " -i \"#{identifier}\" " if identifier

        sign_cmd = 'xcrun codesign --verbose=4 --deep -f ' \
                   "-s \"#{options[:id]}\" \"#{file}\"" \
                   "#{identifier}" \
                   " --entitlements \"#{ios_entitlements_path}\""
        puts "INFO: signing with '#{sign_cmd}'"
        Open3.popen3(sign_cmd) do |_, stdout, stderr, wait_thr|
          out = stdout.read.strip
          err = stderr.read.strip
          puts out
          exit_status = wait_thr.value
          if exit_status == 0
          else
            puts err
            exit 1
          end
        end
      end
    end
  end

  unless system("rm -rf '#{ipa}'")
    msg 'error' do
      puts "could not remove the old ipa at '#{ipa}'"
    end
    exit 1
  end

  puts 'INFO: zipping up Payload'

  FileUtils.cd(work_dir) do
    if Dir.exist?(File.join(work_dir, 'SwiftSupport'))
      zip_input = 'Payload SwiftSupport'
    else
      zip_input = 'Payload'
    end

    unless system("zip -qr #{File.basename(options[:ipa])} #{zip_input}")
      msg 'error' do
        puts "could not zip '#{File.basename(options[:ipa])}' from '#{zip_input}'"
      end
      exit 1
    end
  end

  puts "INFO: finished signing '#{ipa}'"

  system("open #{work_dir}") unless ENV['BRIAR_DONT_OPEN_ON_RESIGN']
end
