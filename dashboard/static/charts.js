/**
 * BantayNet Offline Chart.js Analytics & Filter Toggle Controller
 * Detect-and-alert only. Zero external CDN dependencies.
 */

(function () {
  function initCharts() {
    const dataElement = document.getElementById("chart-data");
    if (!dataElement) return;

    let rawData = null;
    try {
      rawData = JSON.parse(dataElement.textContent || "{}");
    } catch (e) {
      return;
    }
    if (!rawData || !window.Chart) return;

    const colors = {
      cyan: "#06b6d4",
      cyanLight: "#38bdf8",
      red: "#ef4444",
      amber: "#f59e0b",
      blue: "#3b82f6",
      emerald: "#10b981",
      purple: "#a855f7",
      pink: "#ec4899",
      textMuted: "#9ca3af",
      grid: "rgba(255, 255, 255, 0.07)",
    };

    Chart.defaults.color = colors.textMuted;
    Chart.defaults.font.family = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
    Chart.defaults.font.size = 11;

    // 1. Timeline Chart
    const ctxTimeline = document.getElementById("timelineChart");
    if (ctxTimeline) {
      const labels =
        rawData.timeline && rawData.timeline.labels && rawData.timeline.labels.length > 0
          ? rawData.timeline.labels
          : ["No Timeline Data"];
      const counts =
        rawData.timeline && rawData.timeline.counts && rawData.timeline.counts.length > 0
          ? rawData.timeline.counts
          : [0];

      new Chart(ctxTimeline, {
        type: "line",
        data: {
          labels: labels,
          datasets: [
            {
              label: "Alerts",
              data: counts,
              borderColor: colors.cyanLight,
              backgroundColor: "rgba(56, 189, 248, 0.12)",
              borderWidth: 2,
              tension: 0.3,
              fill: true,
              pointBackgroundColor: colors.cyan,
              pointBorderColor: "#0a0e17",
              pointBorderWidth: 1.5,
              pointRadius: 3.5,
              pointHoverRadius: 6,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: "rgba(15, 23, 42, 0.95)",
              borderColor: colors.grid,
              borderWidth: 1,
            },
          },
          scales: {
            x: { grid: { color: colors.grid } },
            y: {
              beginAtZero: true,
              ticks: { precision: 0 },
              grid: { color: colors.grid },
            },
          },
        },
      });
    }

    // 2. Top Sources Chart
    const ctxTop = document.getElementById("topSourcesChart");
    if (ctxTop) {
      const labels =
        rawData.top_sources && rawData.top_sources.labels && rawData.top_sources.labels.length > 0
          ? rawData.top_sources.labels
          : ["No Active Hosts"];
      const counts =
        rawData.top_sources && rawData.top_sources.counts && rawData.top_sources.counts.length > 0
          ? rawData.top_sources.counts
          : [0];

      new Chart(ctxTop, {
        type: "bar",
        data: {
          labels: labels,
          datasets: [
            {
              label: "Alerts",
              data: counts,
              backgroundColor: "rgba(6, 182, 212, 0.65)",
              borderColor: colors.cyan,
              borderWidth: 1,
              borderRadius: 4,
            },
          ],
        },
        options: {
          indexAxis: "y",
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: "rgba(15, 23, 42, 0.95)",
              borderColor: colors.grid,
              borderWidth: 1,
            },
          },
          scales: {
            x: {
              beginAtZero: true,
              ticks: { precision: 0 },
              grid: { color: colors.grid },
            },
            y: { grid: { display: false } },
          },
        },
      });
    }

    // 3. By Rule & ATT&CK Chart
    const ctxRule = document.getElementById("byRuleChart");
    if (ctxRule) {
      const labels =
        rawData.by_rule && rawData.by_rule.labels && rawData.by_rule.labels.length > 0
          ? rawData.by_rule.labels.map(function (r) {
              return r.replace("_", " ").toUpperCase();
            })
          : ["No Detections"];
      const counts =
        rawData.by_rule && rawData.by_rule.counts && rawData.by_rule.counts.length > 0
          ? rawData.by_rule.counts
          : [0];
      const palette = ["#ef4444", "#f59e0b", "#06b6d4", "#3b82f6", "#8b5cf6", "#ec4899", "#10b981"];

      new Chart(ctxRule, {
        type: "doughnut",
        data: {
          labels: labels,
          datasets: [
            {
              data: counts,
              backgroundColor: palette.slice(0, labels.length),
              borderColor: "#111827",
              borderWidth: 2,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: "right",
              labels: { boxWidth: 10, padding: 8, color: colors.textMuted },
            },
            tooltip: {
              backgroundColor: "rgba(15, 23, 42, 0.95)",
              borderColor: colors.grid,
              borderWidth: 1,
            },
          },
          cutout: "62%",
        },
      });
    }

    // 4. Severity Distribution Chart
    const ctxSev = document.getElementById("severityChart");
    if (ctxSev) {
      new Chart(ctxSev, {
        type: "bar",
        data: {
          labels: ["High", "Medium", "Low"],
          datasets: [
            {
              label: "Threat Count",
              data: rawData.by_severity ? rawData.by_severity.counts : [0, 0, 0],
              backgroundColor: [
                "rgba(239, 68, 68, 0.75)",
                "rgba(245, 158, 11, 0.75)",
                "rgba(59, 130, 246, 0.75)",
              ],
              borderColor: [colors.red, colors.amber, colors.blue],
              borderWidth: 1,
              borderRadius: 4,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: "rgba(15, 23, 42, 0.95)",
              borderColor: colors.grid,
              borderWidth: 1,
            },
          },
          scales: {
            x: { grid: { display: false } },
            y: {
              beginAtZero: true,
              ticks: { precision: 0 },
              grid: { color: colors.grid },
            },
          },
        },
      });
    }
  }

  // Global toggle function for filter panel
  window.toggleFilterPanel = function () {
    const body = document.getElementById("filterCollapseBody");
    const label = document.getElementById("filterToggleLabel");
    const icon = document.getElementById("filterChevronIcon");
    if (!body) return;

    const isHidden = body.style.display === "none";
    if (isHidden) {
      body.style.display = "block";
      if (label) label.textContent = "Hide Filters";
      if (icon) icon.style.transform = "rotate(0deg)";
      localStorage.setItem("bantaynet_filters_hidden", "false");
    } else {
      body.style.display = "none";
      if (label) label.textContent = "Show Filters";
      if (icon) icon.style.transform = "rotate(-90deg)";
      localStorage.setItem("bantaynet_filters_hidden", "true");
    }
  };

  document.addEventListener("DOMContentLoaded", function () {
    initCharts();

    const panel = document.getElementById("filterPanel");
    const activeCount = panel ? parseInt(panel.getAttribute("data-active-filters") || "0", 10) : 0;
    const pref = localStorage.getItem("bantaynet_filters_hidden");
    if (pref === "true" && activeCount === 0) {
      const body = document.getElementById("filterCollapseBody");
      const label = document.getElementById("filterToggleLabel");
      const icon = document.getElementById("filterChevronIcon");
      if (body) body.style.display = "none";
      if (label) label.textContent = "Show Filters";
      if (icon) icon.style.transform = "rotate(-90deg)";
    }
  });
})();
