(function () {
  var METRICS = [
    ['zap_high_risk_alerts', 'High'],
    ['zap_medium_risk_alerts', 'Medium'],
    ['zap_low_risk_alerts', 'Low'],
    ['zap_info_risk_alerts', 'Info'],
    ['zap_total_alerts', 'Total'],
    ['zap_risk_score', 'Risk score']
  ];

  window.registerExtension('zap/report_page', function (options) {
    var el = options.el;
    var component = options.component || {};
    var branchLike = options.branchLike || {};
    var baseUrl = window.baseUrl || '';

    var params = new URLSearchParams();
    params.set('component', component.key);
    params.set('metricKeys', METRICS.map(function (m) { return m[0]; }).concat('zap_html_report').join(','));
    if (branchLike.pullRequest) {
      params.set('pullRequest', branchLike.pullRequest);
    } else if (branchLike.branch) {
      params.set('branch', branchLike.branch);
    }

    // The host may place the extension in a flex row: claim the full width explicitly.
    el.style.cssText += ';width:100%;flex:1 1 100%;min-width:0';
    var container = document.createElement('div');
    container.style.cssText = 'display:flex;flex-direction:column;width:100%;height:100%;padding:16px;box-sizing:border-box';
    var status = document.createElement('p');
    status.textContent = 'Loading ZAP report…';
    container.appendChild(status);
    el.appendChild(container);

    // SonarQube shrink-wraps extensions to their content, so a percentage width does not help:
    // size the container from the space left in the window instead.
    function fit() {
      var left = container.getBoundingClientRect().left;
      container.style.width = Math.max(320, window.innerWidth - left - 8) + 'px';
    }
    window.addEventListener('resize', fit);
    fit();

    fetch(baseUrl + '/api/measures/component?' + params.toString(), { credentials: 'same-origin' })
      .then(function (r) {
        if (!r.ok) { throw new Error('HTTP ' + r.status); }
        return r.json();
      })
      .then(function (data) {
        var values = {};
        ((data.component || {}).measures || []).forEach(function (m) { values[m.metric] = m.value; });
        container.removeChild(status);

        if (!Object.keys(values).length) {
          status.textContent = 'No ZAP data for this project. Set sonar.zap.reportPaths / sonar.zap.htmlReportPath and re-run the analysis.';
          container.appendChild(status);
          return;
        }

        var summary = document.createElement('p');
        summary.style.marginBottom = '12px';
        summary.textContent = METRICS
          .filter(function (m) { return values[m[0]] !== undefined; })
          .map(function (m) { return m[1] + ': ' + values[m[0]]; })
          .join('   |   ');
        container.appendChild(summary);

        var html = values.zap_html_report;
        if (!html) {
          var none = document.createElement('p');
          none.textContent = 'No HTML report was stored. Set sonar.zap.htmlReportPath to show it here.';
          container.appendChild(none);
          return;
        }
        // Fully sandboxed: the report is untrusted content, so no scripts and no same-origin access.
        var frame = document.createElement('iframe');
        frame.setAttribute('sandbox', '');
        frame.srcdoc = html;
        frame.style.cssText = 'flex:1;min-height:80vh;width:100%;display:block;border:1px solid #ddd;background:#fff';
        container.appendChild(frame);
      })
      .catch(function (e) {
        status.textContent = 'Failed to load ZAP report: ' + e.message;
        if (!status.parentNode) { container.appendChild(status); }
      });

    return function () {
      window.removeEventListener('resize', fit);
      el.removeChild(container);
    };
  });
})();
