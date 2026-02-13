// Chart configurations and utilities for DDoS Dashboard

// Color schemes
const chartColors = {
    primary: '#3b82f6',
    secondary: '#8b5cf6',
    success: '#10b981',
    warning: '#f59e0b',
    danger: '#ef4444',
    info: '#06b6d4',
    gray: '#6b7280'
};

// Chart defaults
const chartDefaults = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
        legend: {
            position: 'top',
            labels: {
                color: 'rgba(255, 255, 255, 0.8)',
                padding: 20,
                usePointStyle: true
            }
        },
        tooltip: {
            backgroundColor: 'rgba(15, 23, 42, 0.9)',
            titleColor: 'rgba(255, 255, 255, 0.9)',
            bodyColor: 'rgba(255, 255, 255, 0.8)',
            borderColor: 'rgba(255, 255, 255, 0.1)',
            borderWidth: 1,
            cornerRadius: 6,
            padding: 12,
            displayColors: true
        }
    },
    scales: {
        x: {
            grid: {
                color: 'rgba(255, 255, 255, 0.1)'
            },
            ticks: {
                color: 'rgba(255, 255, 255, 0.6)'
            }
        },
        y: {
            grid: {
                color: 'rgba(255, 255, 255, 0.1)'
            },
            ticks: {
                color: 'rgba(255, 255, 255, 0.6)'
            }
        }
    }
};

// Network traffic chart
function createTrafficChart(canvasId, data) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;
    
    return new Chart(ctx.getContext('2d'), {
        type: 'line',
        data: {
            labels: data.labels || [],
            datasets: [
                {
                    label: 'Incoming',
                    data: data.rx || [],
                    borderColor: chartColors.primary,
                    backgroundColor: `${chartColors.primary}20`,
                    tension: 0.4,
                    fill: true,
                    borderWidth: 2
                },
                {
                    label: 'Outgoing',
                    data: data.tx || [],
                    borderColor: chartColors.success,
                    backgroundColor: `${chartColors.success}20`,
                    tension: 0.4,
                    fill: true,
                    borderWidth: 2
                }
            ]
        },
        options: {
            ...chartDefaults,
            plugins: {
                ...chartDefaults.plugins,
                title: {
                    display: true,
                    text: 'Network Traffic',
                    color: 'rgba(255, 255, 255, 0.9)',
                    font: {
                        size: 14
                    }
                }
            },
            scales: {
                ...chartDefaults.scales,
                y: {
                    ...chartDefaults.scales.y,
                    title: {
                        display: true,
                        text: 'Bytes per second',
                        color: 'rgba(255, 255, 255, 0.7)'
                    }
                }
            }
        }
    });
}

// CPU usage chart
function createCPUChart(canvasId, data) {
    return new Chart(document.getElementById(canvasId).getContext('2d'), {
        type: 'line',
        data: {
            labels: data.labels || [],
            datasets: [
                {
                    label: 'CPU Usage',
                    data: data.usage || [],
                    borderColor: chartColors.warning,
                    backgroundColor: `${chartColors.warning}20`,
                    tension: 0.4,
                    fill: true,
                    borderWidth: 2
                }
            ]
        },
        options: {
            ...chartDefaults,
            plugins: {
                ...chartDefaults.plugins,
                title: {
                    display: true,
                    text: 'CPU Usage',
                    color: 'rgba(255, 255, 255, 0.9)'
                }
            },
            scales: {
                ...chartDefaults.scales,
                y: {
                    ...chartDefaults.scales.y,
                    beginAtZero: true,
                    max: 100,
                    title: {
                        display: true,
                        text: 'Percentage (%)',
                        color: 'rgba(255, 255, 255, 0.7)'
                    }
                }
            }
        }
    });
}

// Memory usage chart
function createMemoryChart(canvasId, data) {
    return new Chart(document.getElementById(canvasId).getContext('2d'), {
        type: 'line',
        data: {
            labels: data.labels || [],
            datasets: [
                {
                    label: 'Memory Usage',
                    data: data.usage || [],
                    borderColor: chartColors.info,
                    backgroundColor: `${chartColors.info}20`,
                    tension: 0.4,
                    fill: true,
                    borderWidth: 2
                }
            ]
        },
        options: {
            ...chartDefaults,
            plugins: {
                ...chartDefaults.plugins,
                title: {
                    display: true,
                    text: 'Memory Usage',
                    color: 'rgba(255, 255, 255, 0.9)'
                }
            },
            scales: {
                ...chartDefaults.scales,
                y: {
                    ...chartDefaults.scales.y,
                    beginAtZero: true,
                    max: 100,
                    title: {
                        display: true,
                        text: 'Percentage (%)',
                        color: 'rgba(255, 255, 255, 0.7)'
                    }
                }
            }
        }
    });
}

// Connection types chart
function createConnectionsChart(canvasId, data) {
    return new Chart(document.getElementById(canvasId).getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: ['SYN_RECV', 'ESTABLISHED', 'OTHER'],
            datasets: [{
                data: [
                    data.syn || 0,
                    data.established || 0,
                    data.other || 0
                ],
                backgroundColor: [
                    chartColors.warning,
                    chartColors.success,
                    chartColors.gray
                ],
                borderColor: 'rgba(255, 255, 255, 0.1)',
                borderWidth: 2
            }]
        },
        options: {
            ...chartDefaults,
            cutout: '70%',
            plugins: {
                ...chartDefaults.plugins,
                title: {
                    display: true,
                    text: 'Connection Types',
                    color: 'rgba(255, 255, 255, 0.9)'
                }
            }
        }
    });
}

// Attack frequency chart
function createAttackFrequencyChart(canvasId, data) {
    return new Chart(document.getElementById(canvasId).getContext('2d'), {
        type: 'bar',
        data: {
            labels: data.labels || ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            datasets: [{
                label: 'Attack Attempts',
                data: data.attempts || [12, 19, 8, 15, 22, 18, 14],
                backgroundColor: chartColors.danger,
                borderColor: chartColors.danger,
                borderWidth: 1
            }]
        },
        options: {
            ...chartDefaults,
            plugins: {
                ...chartDefaults.plugins,
                title: {
                    display: true,
                    text: 'Attack Frequency',
                    color: 'rgba(255, 255, 255, 0.9)'
                }
            }
        }
    });
}

// Incident severity chart
function createIncidentSeverityChart(canvasId, data) {
    return new Chart(document.getElementById(canvasId).getContext('2d'), {
        type: 'polarArea',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [
                    data.critical || 0,
                    data.high || 0,
                    data.medium || 0,
                    data.low || 0
                ],
                backgroundColor: [
                    chartColors.danger,
                    chartColors.warning,
                    chartColors.info,
                    chartColors.success
                ],
                borderColor: 'rgba(255, 255, 255, 0.1)',
                borderWidth: 2
            }]
        },
        options: {
            ...chartDefaults,
            plugins: {
                ...chartDefaults.plugins,
                title: {
                    display: true,
                    text: 'Incident Severity Distribution',
                    color: 'rgba(255, 255, 255, 0.9)'
                }
            }
        }
    });
}

// Real-time metrics chart
function createRealtimeMetricsChart(canvasId) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;
    
    const chart = new Chart(ctx.getContext('2d'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Connections',
                    data: [],
                    borderColor: chartColors.primary,
                    backgroundColor: 'transparent',
                    tension: 0.4,
                    borderWidth: 2,
                    yAxisID: 'y'
                },
                {
                    label: 'CPU %',
                    data: [],
                    borderColor: chartColors.warning,
                    backgroundColor: 'transparent',
                    tension: 0.4,
                    borderWidth: 2,
                    yAxisID: 'y1'
                }
            ]
        },
        options: {
            ...chartDefaults,
            interaction: {
                mode: 'index',
                intersect: false
            },
            scales: {
                x: {
                    ...chartDefaults.scales.x,
                    type: 'realtime',
                    realtime: {
                        duration: 60000, // 60 seconds window
                        refresh: 1000,   // Update every second
                        delay: 1000,
                        onRefresh: function(chart) {
                            // This would be updated by real-time data
                        }
                    }
                },
                y: {
                    type: 'linear',
                    display: true,
                    position: 'left',
                    title: {
                        display: true,
                        text: 'Connections'
                    }
                },
                y1: {
                    type: 'linear',
                    display: true,
                    position: 'right',
                    title: {
                        display: true,
                        text: 'CPU %'
                    },
                    grid: {
                        drawOnChartArea: false
                    }
                }
            }
        }
    });
    
    return chart;
}

// Update chart with new data
function updateChart(chart, newData) {
    if (!chart || !newData) return;
    
    // Add new data point
    const now = new Date();
    const timeLabel = `${now.getHours()}:${now.getMinutes()}:${now.getSeconds()}`;
    
    chart.data.labels.push(timeLabel);
    
    // Update datasets
    chart.data.datasets.forEach((dataset, index) => {
        const dataKey = Object.keys(newData)[index];
        if (dataKey && newData[dataKey] !== undefined) {
            dataset.data.push(newData[dataKey]);
            
            // Keep only last N data points
            if (dataset.data.length > 30) {
                dataset.data.shift();
            }
        }
    });
    
    // Keep labels in sync
    if (chart.data.labels.length > 30) {
        chart.data.labels.shift();
    }
    
    chart.update('none');
}

// Create gauge chart
function createGaugeChart(canvasId, value, max = 100, label = '') {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;
    
    // Determine color based on value
    let color;
    const percentage = (value / max) * 100;
    
    if (percentage < 30) {
        color = chartColors.success;
    } else if (percentage < 70) {
        color = chartColors.warning;
    } else {
        color = chartColors.danger;
    }
    
    return new Chart(ctx.getContext('2d'), {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [value, max - value],
                backgroundColor: [color, 'rgba(255, 255, 255, 0.1)'],
                borderWidth: 0,
                circumference: 180,
                rotation: 270
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '80%',
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    enabled: false
                }
            }
        },
        plugins: [{
            id: 'gaugeLabel',
            afterDraw: (chart) => {
                const { ctx, chartArea: { width, height } } = chart;
                ctx.save();
                ctx.font = 'bold 20px Arial';
                ctx.fillStyle = 'rgba(255, 255, 255, 0.9)';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText(`${value}%`, width / 2, height / 2 + 10);
                
                if (label) {
                    ctx.font = '12px Arial';
                    ctx.fillStyle = 'rgba(255, 255, 255, 0.6)';
                    ctx.fillText(label, width / 2, height / 2 + 35);
                }
                
                ctx.restore();
            }
        }]
    });
}

// Create stacked bar chart for firewall stats
function createFirewallStatsChart(canvasId, data) {
    return new Chart(document.getElementById(canvasId).getContext('2d'), {
        type: 'bar',
        data: {
            labels: data.labels || ['INPUT', 'OUTPUT', 'FORWARD'],
            datasets: [
                {
                    label: 'Accepted',
                    data: data.accepted || [0, 0, 0],
                    backgroundColor: chartColors.success,
                    stack: 'Stack 0'
                },
                {
                    label: 'Dropped',
                    data: data.dropped || [0, 0, 0],
                    backgroundColor: chartColors.danger,
                    stack: 'Stack 0'
                },
                {
                    label: 'Rejected',
                    data: data.rejected || [0, 0, 0],
                    backgroundColor: chartColors.warning,
                    stack: 'Stack 0'
                }
            ]
        },
        options: {
            ...chartDefaults,
            plugins: {
                ...chartDefaults.plugins,
                title: {
                    display: true,
                    text: 'Firewall Statistics',
                    color: 'rgba(255, 255, 255, 0.9)'
                }
            },
            scales: {
                ...chartDefaults.scales,
                x: {
                    stacked: true
                },
                y: {
                    stacked: true,
                    title: {
                        display: true,
                        text: 'Packet Count',
                        color: 'rgba(255, 255, 255, 0.7)'
                    }
                }
            }
        }
    });
}

// Create heatmap for attack sources
function createAttackHeatmap(canvasId, data) {
    // This is a simplified heatmap - in production you'd use a proper heatmap library
    return new Chart(document.getElementById(canvasId).getContext('2d'), {
        type: 'bubble',
        data: {
            datasets: [{
                label: 'Attack Sources',
                data: data.points || [],
                backgroundColor: chartColors.danger + '80',
                borderColor: chartColors.danger
            }]
        },
        options: {
            ...chartDefaults,
            plugins: {
                ...chartDefaults.plugins,
                title: {
                    display: true,
                    text: 'Attack Source Heatmap',
                    color: 'rgba(255, 255, 255, 0.9)'
                }
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: 'Time of Day',
                        color: 'rgba(255, 255, 255, 0.7)'
                    }
                },
                y: {
                    title: {
                        display: true,
                        text: 'Attack Intensity',
                        color: 'rgba(255, 255, 255, 0.7)'
                    }
                }
            }
        }
    });
}

// Export chart functions
window.DDOSCharts = {
    createTrafficChart,
    createCPUChart,
    createMemoryChart,
    createConnectionsChart,
    createAttackFrequencyChart,
    createIncidentSeverityChart,
    createRealtimeMetricsChart,
    updateChart,
    createGaugeChart,
    createFirewallStatsChart,
    createAttackHeatmap,
    chartColors
};
