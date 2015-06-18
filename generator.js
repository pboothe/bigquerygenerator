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
var addDatePicklist = function (container) {
  container.append($('<select/>', {
    type: 'select',
    id: 'dateList',
  }))
    .change(updateUI);
  var currentDate = new Date(2009, 1, 1); // this is actually february
  var todayMonth = new Date();
  todayMonth.setDate(1);
  todayMonth.setHours(0);
  todayMonth.setMinutes(0);
  todayMonth.setSeconds(0);
  while (currentDate <= todayMonth) {
    month = (currentDate.getMonth() + 1) + '';
    if (month.length == 1) {
      month = '0' + month;
    }
    formatted_date = currentDate.getFullYear() + '_' + month;

    var sourceTable = '[plx.google:m_lab.' + formatted_date + '.all]';
    var isSelected = ((currentDate.getYear() == todayMonth.getYear()) &&
              (currentDate.getMonth() == todayMonth.getMonth()));

    $('#dateList').append($('<option/>', {
      value: sourceTable,
      text: formatted_date,
      selected: (isSelected),
    }));

    currentDate.setMonth(currentDate.getMonth() + 1); // TODO: Fix this.
  }
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
var updateUI = function () {
  updateOptions();
  updateQuery();
};
var updateOptions = function () {
  $('#packetRetransmitRate').prop('disabled', $('#c2s').is(':checked'));
  $('#averageRTT').prop('disabled', $('#c2s').is(':checked'));
  $('#minimumRTT').prop('disabled', $('#c2s').is(':checked'));
  $('#reachedCongestion').prop('disabled', $('#c2s').is(':checked'));

  // Figure out if geolocation bug affects this table.
  // TODO: Remove this hacky workaround.
  var dateStr = /\d{4}_\d{2}/.exec($('#dateList').val())[0];
  var dateParts = dateStr.split('_');
  var year = parseInt(dateParts[0]);
  var month = parseInt(dateParts[1]);
  var selectedDate = new Date(year, month, 1);
  var geolocationAvailable = true;
  if (selectedDate < new Date(2012, 5, 1)) {
    geolocationAvailable = false;
  }
  $('#clientGeolocation').prop('disabled', !geolocationAvailable);
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
    selectAttributes.push('connection_spec.client_geolocation.latitude AS latitude');
    selectAttributes.push('connection_spec.client_geolocation.longitude AS longitude');
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
      whereClauses.push(
          'web100_log_entry.snap.CountRTT > 0');
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

  Object.keys(nonNullFields).forEach(function(fieldName) {
      whereClauses.unshift(fieldName + ' IS NOT NULL');
  });

  sourceTable = $('#dateList').val();

  query = ''
  query += 'SELECT\n';
  query += '  ' + selectAttributes.join(',\n  ');
  query += '\n';
  query += 'FROM\n';
  query += '  ' + sourceTable + '\n';
  query += 'WHERE\n';
  query += '  ' + whereClauses.join('\n  AND ');
  //query += '\n;';
  $('#queryWindow').html(nl2br(query.replace(/ /g, '&nbsp;')));
};
$(function () {
  addRadioButton($('#optionsTestType'), 's2c', 'direction', 'Server to Client (Download)', true);
  addRadioButton($('#optionsTestType'), 'c2s', 'direction', 'Client to Server (Upload)', false);
  addDatePicklist($('#optionsDates'));
  addCheckbox($('#optionsValues'), 'testId', 'Test ID', false);
  addCheckbox($('#optionsValues'), 'logTime', 'Test Time', false);
  addCheckbox($('#optionsValues'), 'serverIPv4', 'Server IPv4 Address', false);
  addCheckbox($('#optionsValues'), 'clientIPv4', 'Client IPv4 Address', false);
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

  updateQuery();
});
