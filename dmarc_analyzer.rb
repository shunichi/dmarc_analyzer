require 'dmarc_parser'
require 'resolv'
require 'csv'
require 'zip'

class DmarcAnalyzerReport
  class Record
    attr_reader :source_ip, :header_from, :count, :host, :spf_alignment, :dkim_alignment, :spf_result, :spf_domain, :dkim_result, :dkim_domain, :additional_dkim_results, :dmarc_pass, :arc_pass

    def initialize(source_record)
      @source_ip = source_record.source_ip
      @count = source_record.count
      @header_from = source_record.header_from
      begin
        @host = Resolv.getname(source_ip)
      rescue Resolv::ResolvError
      end

      # SPF Result は一つだけ
      spf_auth_result = source_record.auth_results.find { |auth_result| auth_result.type == 'spf' }
      if spf_auth_result
        @spf_result = spf_auth_result.result
        @spf_domain = spf_auth_result.domain
      end
      # DKIM Result は複数ある可能性がある
      dkim_auth_results = source_record.auth_results.select { |auth_result| auth_result.type == 'dkim' }
      dkim_auth_results = dkim_auth_results.partition { |auth_result| auth_result.domain.end_with?(header_from) }.flatten
      if (first_dkim_auth_result = dkim_auth_results.first)
        @dkim_result = first_dkim_auth_result.result
        @dkim_domain = first_dkim_auth_result.domain
      end
      @additional_dkim_results = dkim_auth_results
        .drop(1)
        .map { |auth_result| "#{auth_result.domain}/#{auth_result.result}" }
        .sort
        .join("\n")

      @spf_alignment = source_record.spf
      @dkim_alignment = source_record.dkim
      @dmarc_pass = (spf_result == 'pass' && spf_alignment == 'pass') || (dkim_result == 'pass' && dkim_alignment == 'pass')
      @arc_pass = source_record.reasons.any? { |reason| reason.comment == 'arc=pass'}
    end

    def dmarc_or_arc_pass
      dmarc_pass || arc_pass
    end

    def key
      [source_ip, header_from, spf_alignment, dkim_alignment, spf_result, spf_domain, dkim_result, dkim_domain, additional_dkim_results, arc_pass]
    end

    def add_count(other_count)
      @count += other_count
    end
  end

  attr_reader :records

  def initialize(filename = nil)
    if filename
      load(filename)
    else
      @records = []
    end
  end

  def load(filename)
    xml_string = read_file(filename)
    report = DmarcParser::Report.new(xml_string)
    @records = report.records.map do |source_record|
      Record.new(source_record)
    end
  end

  def merge!(other)
    hash = records.to_h { |record| [record.key, record] }
    other.records.each do |record|
      if (matched = hash[record.key])
        matched.add_count(record.count)
      else
        records.push(record)
        hash[record.key] = record
      end
    end
  end

  def to_csv
    CSV.generate do |csv|
      header = [
        'Source IP',
        'Source Host Name',
        'Header From',
        'Mail Count',
        'DMARC OR ARC Result',
        'DMARC Result',
        'ARC Result',
        'SPF Alignment',
        'DKIM Alignment',
        'SPF Result',
        'SPF Domain',
        'DKIM Result',
        'DKIM Domain',
        'Additonal DKIM',
      ]
      csv << header
      records.each do |record|
        row = [
          record.source_ip,
          record.host,
          record.header_from,
          record.count,
          record.dmarc_or_arc_pass ? 'pass' : 'fail',
          record.dmarc_pass ? 'pass' : 'fail',
          record.arc_pass ? 'pass' : '',
          record.spf_alignment,
          record.dkim_alignment,
          record.spf_result,
          record.spf_domain,
          record.dkim_result,
          record.dkim_domain,
          record.additional_dkim_results,
        ]
        csv << row
      end
    end
  end

  def info
    mail_total = 0
    spf_alignment_pass_total = 0
    dmarc_pass_total = 0
    dmarc_or_arc_pass_total = 0
    dmarc_and_arc_fail_total = 0
    records.each do |record|
      mail_total += record.count
      spf_alignment_pass_total += record.count if record.spf_alignment == 'pass'
      dmarc_pass_total += record.count if record.dmarc_pass
      dmarc_or_arc_pass_total += record.count if record.dmarc_or_arc_pass
      dmarc_and_arc_fail_total += record.count unless record.dmarc_or_arc_pass
    end
    {
      mail_total:,
      spf_alignment_pass_total:,
      dmarc_pass_total:,
      dmarc_or_arc_pass_total:,
      dmarc_and_arc_fail_total:,
    }
  end

  private

  def read_file(filename)
    case File.extname(filename).downcase
    when '.zip'
      read_zip_file(filename)
    when '.gz'
      read_gzip_file(filename)
    when '.xml'
      File.read(filename)
    end
  end

  def read_zip_file(filename)
    content = nil
    Zip::File.open(filename) do |zip_file|
      zip_file.each do |entry|
        if File.extname(entry.name).downcase == '.xml'
          content = entry.get_input_stream.read
          break;
        end
      end
    end
    content
  end

  def read_gzip_file(filename)
    Zlib::GzipReader.open(filename).read
  end
end

def format_float(float)
  "%.1f" % float
end

analyzer_report = DmarcAnalyzerReport.new
ARGV.each do |filename|
  puts "Reading #{filename}"
  analyzer_report.merge!(DmarcAnalyzerReport.new(filename))
end
csv_text = analyzer_report.to_csv
File.write('dmarc_analyzer_result.csv', csv_text)

info = analyzer_report.info
valid_transfer_count = info[:dmarc_or_arc_pass_total] - info[:spf_alignment_pass_total]
if info[:mail_total] > 0
  valid_percent = info[:dmarc_or_arc_pass_total] * 100.0 / info[:mail_total]
  valid_direct_percent = info[:spf_alignment_pass_total] * 100.0 / info[:mail_total]
  valid_transfer_percent = valid_transfer_count * 100.0 / info[:mail_total]
  invalid_percent = info[:dmarc_and_arc_fail_total] * 100.0 / info[:mail_total]
end
puts "全メール: #{info[:mail_total]}"
puts "正: #{info[:dmarc_or_arc_pass_total]} (#{format_float valid_percent}%)"
puts "正(直接): #{info[:spf_alignment_pass_total]} (#{format_float valid_direct_percent}%)"
puts "正(転送): #{valid_transfer_count} (#{format_float valid_transfer_percent}%)"
puts "不正: #{info[:dmarc_and_arc_fail_total]} (#{format_float invalid_percent}%)"
