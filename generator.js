var nl2br = function(str) {
  return (str + '').replace(/([^>\r\n]?)(\r\n|\n\r|\r|\n)/g, '$1<br />$2');
}

var addCheckbox = function(container, id, labelValue, isChecked) {
  container.append($('<input/>', {
    type: 'checkbox',
    id: id,
    checked: isChecked,
  })).change(updateUI)
    .append($('<label/>', {
      text: labelValue
  }))
  .append($('<br/>'));
};

var addRadioButton = function(container, id, name, labelValue, isChecked) {
  container.append($('<input/>', {
    type: 'radio',
    id: id,
    name: name,
    checked: isChecked,
  })).change(updateUI)
    .append($('<label/>', {
      text: labelValue
    }))
    .append($('<br/>'));
};

var addIPRangeFilter = function(container) {
  addCheckbox(container, 'ipRangeCheckbox', "Clients within specified IP ranges (e.g. 1.2.3.4/24, 2.3.4.5/30)", false);
  container.append($('<input/>', {
    type: 'text',
    id: 'ipRange',
    disabled: true,
  })).change(updateUI);
};

function dot2num(dot) {
  var d = dot.split('.');
  return ((((((+d[0])*256)+(+d[1]))*256)+(+d[2]))*256)+(+d[3]);
}

//https://gist.github.com/binarymax/6114792
var parseCIDR = function(CIDR) {
  // Beginning IP address
  var beg = CIDR.substr(CIDR,CIDR.indexOf('/'));
  var end = beg;
  var off = (1<<(32-parseInt(CIDR.substr(CIDR.indexOf('/')+1))))-1;
  var sub = beg.split('.').map(function(a){return parseInt(a)});

  // An IPv4 address is just an UInt32...
  var buf = new ArrayBuffer(4); //4 octets
  var i32 = new Uint32Array(buf);

  // Get the UInt32, and add the bit difference
  i32[0]  = (sub[0]<<24) + (sub[1]<<16) + (sub[2]<<8)
             + (sub[3]) + off;

  // Recombine into an IPv4 string:
  var end = Array.apply([], new Uint8Array(buf)).reverse().join('.');
  return [dot2num(beg),dot2num(end)];
}

var parseIPRanges = function(ipRangesRaw) {
  var parsedRanges = [];
  var ipRangesStripped = ipRangesRaw.replace(/[^0-9\.,/]+/g, '');
  var ipRanges = ipRangesStripped.split(',');
  ipRanges.forEach(function (ipRange) {
    if (!/(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?/.exec(ipRange)) {
      return;
    }
    if (ipRange.indexOf('/') < 0) {
      ipParsed = dot2num(ipRange);
      parsedRanges.push([ipParsed, ipParsed]);
    } else {
      parsedRanges.push(parseCIDR(ipRange));
    }
  });
  return parsedRanges;
};

var updateUI = function () {
  updateOptions();
  updateQuery();
};

var updateOptions = function () {
  $('#packetRetransmitRate').prop('disabled', $('#c2s').is(':checked'));
  $('#averageRTT').prop('disabled', $('#c2s').is(':checked'));
  $('#minimumRTT').prop('disabled', $('#c2s').is(':checked'));
  $('#reachedCongestion').prop('disabled', $('#c2s').is(':checked'));
  $('#ipRange').prop('disabled', !$('#ipRangeCheckbox').is(':checked'));
};

var updateQuery = function () {
  selectAttributes = []
  whereClauses = []
  nonNullFields = {}

  if ($('#testId').is(':checked')) {
    selectAttributes.push('test_id');
  }
  if ($('#logTime').is(':checked')) {
    selectAttributes.push('web100_log_entry.log_time AS log_time');
  }
  if ($('#serverIPv4').is(':checked')) {
    selectAttributes.push('web100_log_entry.connection_spec.remote_ip AS server_ip_v4');
  }
  if ($('#clientIPv4').is(':checked')) {
    selectAttributes.push('web100_log_entry.connection_spec.remote_ip AS client_ip_v4');
  }
  if ($('#clientHostname').is(':checked')) {
    selectAttributes.push('connection_spec.client_hostname AS client_hostname');
  }
  if ($('#clientApplication').is(':checked')) {
    selectAttributes.push('connection_spec.client_application AS client_application');
  }
  if ($('#clientBrowser').is(':checked')) {
    selectAttributes.push('connection_spec.client_browser AS client_browser');
  }
  if ($('#clientOs').is(':checked')) {
    selectAttributes.push('connection_spec.client_os AS client_os');
  }
  if (!$('#clientGeolocation').is(':disabled') &&
     $('#clientGeolocation').is(':checked')) {
    selectAttributes.push('connection_spec.client_geolocation.city AS client_city');
    selectAttributes.push('connection_spec.client_geolocation.country_code AS client_country');
    selectAttributes.push('connection_spec.client_geolocation.latitude AS client_latitude');
    selectAttributes.push('connection_spec.client_geolocation.longitude AS client_longitude');
  }

  if ($('#throughput').is(':checked')) {
    if ($('#s2c').is(':checked')) {
      selectAttributes.push(
          '8 * (web100_log_entry.snap.HCThruOctetsAcked /\n' +
          '        (web100_log_entry.snap.SndLimTimeRwin +\n' +
          '         web100_log_entry.snap.SndLimTimeCwnd +\n' +
          '         web100_log_entry.snap.SndLimTimeSnd)) AS ' +
          'download_mbps');
    } else {
      selectAttributes.push(
          '8 * (web100_log_entry.snap.HCThruOctetsReceived /\n' +
          '         web100_log_entry.snap.Duration) AS upload_mbps');
    }
  }
  if (!$('#averageRTT').is(':disabled') &&
    $('#averageRTT').is(':checked')) {
      selectAttributes.push(
          '(web100_log_entry.snap.SumRTT /\n' +
          '     web100_log_entry.snap.CountRTT) ' +
          'AS avg_rtt');
  }
  if (!$('#minimumRTT').is(':disabled') &&
      $('#minimumRTT').is(':checked')) {
      selectAttributes.push(
          'web100_log_entry.snap.MinRTT AS min_rtt');
  }
  if (!$('#packetRetransmitRate').is(':disabled') &&
      $('#packetRetransmitRate').is(':checked')) {
      selectAttributes.push(
          '(web100_log_entry.snap.SegsRetrans /\n' +
          '     web100_log_entry.snap.DataSegsOut) ' +
          'AS packet_retransmit_rate');
  }

  whereClauses.push('project = 0');
  whereClauses.push('web100_log_entry.is_last_entry = True');

  if ($('#s2c').is(':checked')) {
      whereClauses.push('connection_spec.data_direction = 1');
  } else {
      nonNullFields['connection_spec.data_direction'] = true;
      whereClauses.push('connection_spec.data_direction = 0');
  }
  if (!$('#reachedCongestion').is(':disabled') &&
      $('#reachedCongestion').is(':checked')) {
      whereClauses.push('web100_log_entry.snap.CongSignals > 0');
  }
  if ($('#exchanged8192').is(':checked')) {
      var octetsFieldName = '';
      if ($('#s2c').is(':checked')) {
          octetsFieldName = 'HCThruOctetsAcked';
      } else {
          octetsFieldName = 'HCThruOctetsReceived';
      }
      whereClauses.push(
          'web100_log_entry.snap.' + octetsFieldName + ' >= 8192');
  }
  if ($('#completedThreeWayHandshake').is(':checked')) {
      whereClauses.push(
          '(web100_log_entry.snap.State == 1\n' +
          '    OR (web100_log_entry.snap.State >= 5\n' +
          '        AND web100_log_entry.snap.State <= 11))');
  }
  if ($('#metMinDuration').is(':checked')) {
      var minDuration = 9 * Math.pow(10, 6);
      if ($('#s2c').is(':checked')) {
          nonNullFields['web100_log_entry.snap.SndLimTimeRwin'] = true;
          nonNullFields['web100_log_entry.snap.SndLimTimeCwnd'] = true;
          nonNullFields['web100_log_entry.snap.SndLimTimeSnd'] = true;
          whereClauses.push(
              '(web100_log_entry.snap.SndLimTimeRwin +\n' +
              '       web100_log_entry.snap.SndLimTimeCwnd +\n' +
              '       web100_log_entry.snap.SndLimTimeSnd) >= ' + minDuration);
      } else {
          whereClauses.push(
              'web100_log_entry.snap.Duration >= ' + minDuration);
      }
  }
  if ($('#didNotExceedMaxDuration').is(':checked')) {
    var maxDuration = 36 * Math.pow(10, 8);
    if ($('#s2c').is(':checked')) {
        nonNullFields['web100_log_entry.snap.SndLimTimeRwin'] = true;
        nonNullFields['web100_log_entry.snap.SndLimTimeCwnd'] = true;
        nonNullFields['web100_log_entry.snap.SndLimTimeSnd'] = true;
        whereClauses.push(
            '(web100_log_entry.snap.SndLimTimeRwin +\n' +
            '       web100_log_entry.snap.SndLimTimeCwnd +\n' +
            '       web100_log_entry.snap.SndLimTimeSnd) < ' + maxDuration);
    } else {
        nonNullFields['web100_log_entry.snap.Duration'] = true;
        whereClauses.push(
              'web100_log_entry.snap.Duration < ' + maxDuration);
    }
  }
  if (($('#s2c').is(':checked')) &&
      !$('#hadMinRTT').is(':disabled') &&
      $('#hadMinRTT').is(':checked')) {
      whereClauses.push('web100_log_entry.snap.CountRTT > 10');
  }
  if ($('#ipRangeCheckbox').is(':checked')) {
    var ipRanges = parseIPRanges($('#ipRange').val());
    if (ipRanges.length > 0) {
      var clientIpClauses = []
      ipRanges.forEach(function (ipRange) {
        clientIpClauses.push('PARSE_IP(web100_log_entry.connection_spec.remote_ip) ' +
            'BETWEEN ' + ipRange[0] + ' AND ' + ipRange[1]);
      });
      whereClauses.push('(' + clientIpClauses.join('\n       OR ') + ')');
    }
  }

  Object.keys(nonNullFields).forEach(function(fieldName) {
      whereClauses.unshift(fieldName + ' IS NOT NULL');
  });

  sourceTable = $('#dateList').val();

  query = ''
  query += 'SELECT\n';
  query += '  ' + selectAttributes.join(',\n  ');
  query += '\n';
  query += 'FROM\n';
  query += '  [plx.google:m_lab.ndt.all]\n';
  query += 'WHERE\n';
  query += '  ' + whereClauses.join('\n  AND ');
  //query += '\n;';
  $('#queryWindow').html(nl2br(query.replace(/ /g, '&nbsp;')));
};
$(function () {
  addRadioButton($('#optionsTestType'), 's2c', 'direction', 'Server to Client (Download)', true);
  addRadioButton($('#optionsTestType'), 'c2s', 'direction', 'Client to Server (Upload)', false);
  addCheckbox($('#optionsValues'), 'testId', 'Test ID', false);
  addCheckbox($('#optionsValues'), 'logTime', 'Test Time', false);
  addCheckbox($('#optionsValues'), 'serverIPv4', 'Server IPv4 Address', true);
  addCheckbox($('#optionsValues'), 'clientIPv4', 'Client IPv4 Address', true);
  addCheckbox($('#optionsValues'), 'clientHostname', 'Client Hostname', false);
  addCheckbox($('#optionsValues'), 'clientApplication', 'Client Application Name', false);
  addCheckbox($('#optionsValues'), 'clientBrowser', 'Client Browser', false);
  addCheckbox($('#optionsValues'), 'clientOs', 'Client OS', false);
  addCheckbox($('#optionsValues'), 'clientGeolocation', 'Client Geolocation', false);
  addCheckbox($('#optionsValues'), 'throughput', 'Throughput', true);
  addCheckbox($('#optionsValues'), 'averageRTT', 'Average RTT', true);
  addCheckbox($('#optionsValues'), 'minimumRTT', 'Minimum RTT', true);
  addCheckbox($('#optionsValues'), 'packetRetransmitRate', 'Packet Retransmit Rate', true);
  addCheckbox($('#optionsFilters'), 'reachedCongestion', 'Reached Congestion', true);
  addCheckbox($('#optionsFilters'), 'exchanged8192', 'Exchanged at least 8192 bytes', true);
  addCheckbox($('#optionsFilters'), 'completedThreeWayHandshake', 'Completed three-way TCP handshake', true);
  addCheckbox($('#optionsFilters'), 'metMinDuration', 'Met minimum duration threshold', true);
  addCheckbox($('#optionsFilters'), 'didNotExceedMaxDuration', 'Did not exceed maximum duration threshold', true);
  addCheckbox($('#optionsFilters'), 'hadMinRTT', 'Met minimum RTT measurements', true);
  addIPRangeFilter($('#optionsFilters'));

  updateQuery();
});
