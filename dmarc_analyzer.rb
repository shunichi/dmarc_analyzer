require 'dmarc_parser'
require 'resolv'
require 'csv'

xml_string = File.read(ARGV.shift)
report = DmarcParser::Report.new(xml_string)
csv_text = CSV.generate do |csv|
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
  report.records.each do |record|
    host = Resolv.getname(record.source_ip)
    header_from = record.header_from
    auth_results_hash = {
      spf: {},
      dkim: {}
    }
    # SPF Result は一つだけ
    spf_result = record.auth_results.find { |auth_result| auth_result.type == 'spf' }
    if spf_result
      auth_results_hash[:spf] = {
        domain: spf_result.domain,
        result: spf_result.result,
      }
    end
    # DKIM Result は複数ある可能性がある
    dkim_results = record.auth_results.select { |auth_result| auth_result.type == 'dkim' }
    dkim_results = dkim_results.partition { |auth_result| auth_result.domain.end_with?(header_from) }.flatten
    if (first_dkim_result = dkim_results.first)
      auth_results_hash[:dkim] = {
        domain: first_dkim_result.domain,
        result: first_dkim_result.result,
      }
    end
    additional_dkim_results = dkim_results.drop(1).map { |auth_result| "#{auth_result.domain}/#{auth_result.result}" }.join("\n")

    dmarc_pass = record.dkim == 'pass' && record.spf == 'pass'
    arc_pass = record.reasons.any? { |reason| reason.comment == 'arc=pass'}
    row = [
      record.source_ip,
      host,
      record.header_from,
      record.count,
      dmarc_pass || arc_pass ? 'pass' : 'fail',
      dmarc_pass ? 'pass' : 'fail',
      arc_pass ? 'pass' : '',
      record.spf,
      record.dkim,
      auth_results_hash[:spf][:result],
      auth_results_hash[:spf][:domain],
      auth_results_hash[:dkim][:result],
      auth_results_hash[:dkim][:domain],
      additional_dkim_results,
    ]
    csv << row
  end
end
File.write('result.csv', csv_text)
