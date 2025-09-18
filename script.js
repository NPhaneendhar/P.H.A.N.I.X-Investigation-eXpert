// --- GLOBAL STATE & INITIALIZATION ---
let analysisResults = {};
let chainOfCustody = [];
let chatHistory = [];
let mapInstance = null;
let currentFileForHexView = null;

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

// --- NEW: Security Hardening - HTML Sanitizer ---
function sanitizeHTML(str) {
    const temp = document.createElement('div');
    temp.textContent = str;
    return temp.innerHTML;
}

const threatDatabase = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "WannaCry Ransomware",
    "e889544aff85ffaf8b0d0da705105dee7c97fe266fee5ae42d97b3af8d372185": "Emotet Trojan",
    "1a1a9999a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1": "EICAR Test File"
};

document.addEventListener('DOMContentLoaded', () => {
    const guideTabs = document.querySelectorAll('.guide-tab-btn');
    const guideContents = document.querySelectorAll('.guide-tab-content');

    guideTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            // Deactivate all
            guideTabs.forEach(t => t.classList.remove('active'));
            guideContents.forEach(c => c.classList.remove('active'));

            // Activate clicked tab and corresponding content
            tab.classList.add('active');
            const tabId = tab.dataset.tab;
            document.getElementById(`guide-${tabId}`).classList.add('active');
        });
    });


    const themeToggle = document.getElementById('theme-toggle');
    const animationToggle = document.getElementById('animation-toggle');
    const body = document.body;

    function applyTheme(theme) {
        if (theme === 'light') {
            body.classList.add('light-theme');
            if (themeToggle) themeToggle.checked = true;
        } else {
            body.classList.remove('light-theme');
            if (themeToggle) themeToggle.checked = false;
        }
        if (typeof updateConstellationColors === 'function') {
            updateConstellationColors();
        }
        // NEW: Update map tiles if map is active
        if (mapInstance) {
            updateMapTheme();
        }
    }

    // Load theme preference on startup
    const savedTheme = localStorage.getItem('theme');
    const prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
    applyTheme(savedTheme || (prefersLight ? 'light' : 'dark'));

    themeToggle.addEventListener('change', () => {
        const newTheme = themeToggle.checked ? 'light' : 'dark';
        localStorage.setItem('theme', newTheme);
        applyTheme(newTheme);
    });

    // --- NEW: Animation Setting ---
    const animationsDisabled = localStorage.getItem('animationsDisabled') === 'true';
    if (animationToggle) {
        animationToggle.checked = animationsDisabled;
        if (animationsDisabled) {
            body.classList.add('no-animations');
        }
        animationToggle.addEventListener('change', () => {
            localStorage.setItem('animationsDisabled', animationToggle.checked);
            alert('Background animation setting changed. The page will reload to apply it.');
            location.reload();
        });
    }

    // --- NEW: Default User Settings ---
    const settingInvestigatorName = document.getElementById('setting-investigator-name');
    const settingOrgName = document.getElementById('setting-org-name');
    const reportInvestigatorName = document.getElementById('investigator-name');
    const reportOrgName = document.getElementById('org-name');

    // Listen for changes in the settings card and update localStorage + report card
    settingInvestigatorName.addEventListener('input', () => {
        const name = settingInvestigatorName.value;
        localStorage.setItem('defaultInvestigatorName', name);
        if (reportInvestigatorName) {
            reportInvestigatorName.value = name;
        }
    });

    settingOrgName.addEventListener('input', () => {
        const org = settingOrgName.value;
        localStorage.setItem('defaultOrgName', org);
        if (reportOrgName) {
            reportOrgName.value = org;
        }
    });

    // --- Intersection Observer for scroll-in animations ---
    const observerOptions = {
        root: null, // Use the viewport as the root
        rootMargin: '0px',
        threshold: 0.1 // Trigger when 10% of the element is visible
    };

    const observer = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('is-visible');
                observer.unobserve(entry.target); // Ensure animation only runs once
            }
        });
    }, observerOptions);

    // UPDATED: Observer now watches for all revealable elements
    document.querySelectorAll('.tool-card, .reveal-on-scroll').forEach(el => {
        observer.observe(el);

        // Pause background animation when tab is not visible
        document.addEventListener('visibilitychange', () => { window.isAnimationPaused = document.hidden; });
    });

    // --- Drag and Drop File Input Logic ---
    document.querySelectorAll('input[type="file"]').forEach(fileInput => {
        const dropZone = fileInput.closest('.input-group');
        if (!dropZone) return;

        // Add a visual cue
        if (!dropZone.querySelector('.drop-zone-text')) {
            const p = document.createElement('p');
            p.textContent = 'or drag & drop file';
            p.style.textAlign = 'center';
            p.style.color = 'var(--text-secondary)';
            p.style.fontSize = '0.8rem';
            p.style.marginTop = '0.5rem';
            p.style.pointerEvents = 'none'; // Make sure it doesn't interfere with clicks
            p.classList.add('drop-zone-text');
            fileInput.insertAdjacentElement('afterend', p);
        }

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, preventDefaults, false);
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => dropZone.classList.add('drag-over'), false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => dropZone.classList.remove('drag-over'), false);
        });

        dropZone.addEventListener('drop', (e) => {
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                fileInput.files = files;
                const event = new Event('change', { bubbles: true });
                fileInput.dispatchEvent(event);
            }
        }, false);

        // Add a click listener to allow re-selecting the same file, which will trigger the 'change' event
        fileInput.addEventListener('click', (e) => {
            e.target.value = null;
        });
    });
    ['dragenter', 'dragover', 'drop'].forEach(eventName => { document.body.addEventListener(eventName, preventDefaults, false); });

    // Close modals by clicking on the overlay
    document.querySelectorAll('.modal-overlay').forEach(overlay => {
        overlay.addEventListener('click', (event) => {
            // Only close if the click is on the overlay itself, not its children
            if (event.target === overlay) {
                overlay.classList.remove('active');
            }
        });
    });

    // --- NEW: Keyboard Shortcuts (Accessibility & Pro-user feature) ---
    document.addEventListener('keydown', (event) => {
        // --- Escape Key: Go back / Close ---
        if (event.key === 'Escape') {
            const activeModal = document.querySelector('.modal-overlay.active');
            if (activeModal) {
                activeModal.classList.remove('active');
                return; // Prioritize closing modals
            }
    
            const toolSection = document.querySelector('.tool-section');
            if (toolSection && toolSection.classList.contains('single-view')) {
                const singleViewToggleBtn = document.getElementById('single-view-toggle-btn');
                if (singleViewToggleBtn) {
                    singleViewToggleBtn.click();
                    showToast('Exited Single Tool View', 'info');
                }
            }
        }
    
        // --- Enter Key: Trigger primary action ---
        if (event.key === 'Enter' && !event.shiftKey) { // Exclude Shift+Enter for newlines in textareas
            const activeElement = document.activeElement;
            if (!activeElement || activeElement.tagName === 'BUTTON' || activeElement.tagName === 'A') {
                return; // Let default behavior handle buttons and links
            }
    
            const parentCard = activeElement.closest('.tool-card, .modal-content');
            if (parentCard) {
                const primaryButton = parentCard.querySelector('button:not(.secondary)');
                if (primaryButton && !primaryButton.disabled) {
                    primaryButton.click();
                    event.preventDefault(); // Prevent default form submission
                }
            }
        }
    });

    // --- NEW: Centralized Event Delegation for Actions ---
    document.body.addEventListener('click', (e) => {
        const target = e.target.closest('[data-action]');
        if (!target) return;

        const action = target.dataset.action;
        const cardId = target.dataset.card;
        const modalId = target.dataset.modal;

        switch (action) {
            case 'run-integrity-scan': runAnalysis('integrity-card', generateHash); break;
            case 'run-carve': runAnalysis('integrity-card', findAndCarveSignatures); break;
            case 'run-comparison': runAnalysis('comparison-card', compareFiles); break;
            case 'run-metadata': runAnalysis('metadata-card', analyzeMetadata); break;
            case 'get-metadata-insights': getMetadataAIInsights(); break;
            case 'run-stego': runAnalysis('stego-card', analyzeSteganography); break;
            case 'run-password': runAnalysis('password-card', analyzePassword); break;
            case 'run-network': runAnalysis('network-card', analyzeNetworkAdvanced); break;
            case 'get-network-insights': getNetworkAIInsights(); break;
            case 'export-pdf': exportToPDF(); break;
            case 'clear-all-settings': clearAllSettings(); break;
            case 'submit-manual-coc': submitManualCoCEntry(); break;
            case 'clear-tool-state': if (cardId) clearToolState(cardId); break;
            case 'highlight-card': if (cardId) highlightToolCard(cardId); break;
            case 'close-modal': if (modalId) document.getElementById(modalId).classList.remove('active'); break;
        }
    });

    // --- NEW: Specific Event Listeners for non-delegated actions ---
    const heroBeginBtn = document.getElementById('hero-begin-btn');
    if (heroBeginBtn) {
        heroBeginBtn.addEventListener('click', () => document.getElementById('integrity-card').scrollIntoView({ behavior: 'smooth' }));
    }
    const heroGuideBtn = document.getElementById('hero-guide-btn');
    if (heroGuideBtn) {
        heroGuideBtn.addEventListener('click', () => document.getElementById('guide-modal').classList.add('active'));
    }
    const passwordInput = document.getElementById('password-input');
    if (passwordInput) {
        passwordInput.addEventListener('input', updatePasswordStrengthBarVisuals);
    }
    const copyCocBtn = document.getElementById('copy-coc-btn');
    if (copyCocBtn) {
        copyCocBtn.addEventListener('click', () => copyToClipboard(document.getElementById('modal-body').textContent, copyCocBtn));
    }
    const verifyCocBtn = document.getElementById('verify-coc-btn');
    if (verifyCocBtn) {
        verifyCocBtn.addEventListener('click', () => verifyChainOfCustody(true));
    }

    document.getElementById('timeline-view-btn').addEventListener('click', openTimelineModal);
    document.getElementById('add-coc-entry-btn').addEventListener('click', openAddCocModal);

    // Add simple feedback for file selection
    document.querySelectorAll('input[type="file"]').forEach(input => {
        input.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) {
                const output = e.target.closest('.tool-card-content').querySelector('.output');
                if (output) output.innerHTML = `File '${file.name}' selected. Ready for analysis.`;
            }
        });
    });

    resetSession();

    // --- NEW: Single View Mode Logic ---
    const singleViewToggleBtn = document.getElementById('single-view-toggle-btn');
    const toolSection = document.querySelector('.tool-section');
    const toolNavigator = document.querySelector('.tool-navigator');
    const toolNavLinks = document.querySelectorAll('.tool-navigator .navigator-list a');
    const toolCards = document.querySelectorAll('.tool-section .tool-card');
    const grid = document.querySelector('.tool-grid');

    if (singleViewToggleBtn && toolSection && toolNavigator && toolNavLinks.length > 0 && grid) {
        singleViewToggleBtn.addEventListener('click', () => {
            toolSection.classList.toggle('single-view');
            singleViewToggleBtn.classList.toggle('active');

            const isSingleView = toolSection.classList.contains('single-view');
            toolNavigator.style.display = isSingleView ? 'block' : 'none';

            if (isSingleView) {
                // Deactivate all, then activate the first one
                toolCards.forEach(card => card.classList.remove('active-tool'));
                if (toolCards.length > 0) {
                    toolCards[0].classList.add('active-tool');
                }
                // Also update nav links
                toolNavLinks.forEach(link => link.classList.remove('active'));
                if (toolNavLinks.length > 0) {
                    toolNavLinks[0].classList.add('active');
                }
            } else {
                // When exiting single view, remove active state from all
                toolCards.forEach(card => card.classList.remove('active-tool'));
                grid.style.height = ''; // Reset height
            }
        });

        toolNavLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const targetId = link.getAttribute('href');
                const targetCard = document.querySelector(targetId);
                const currentActiveCard = document.querySelector('.tool-section .tool-card.active-tool');

                if (targetCard && currentActiveCard !== targetCard) {
                    // 1. Set grid to current card's height to prevent page jump
                    if (currentActiveCard) {
                        grid.style.height = `${currentActiveCard.offsetHeight}px`;
                    }

                    // 2. Update nav links
                    toolNavLinks.forEach(l => l.classList.remove('active'));
                    link.classList.add('active');

                    // 3. Hide current card and show target card
                    if (currentActiveCard) {
                        currentActiveCard.classList.remove('active-tool');
                    }
                    toolCards.forEach(card => card.classList.remove('active-tool'));
                    targetCard.classList.add('active-tool');

                    // 4. Animate grid height to new card's height
                    requestAnimationFrame(() => {
                        const newHeight = targetCard.offsetHeight;
                        grid.style.height = `${newHeight}px`;

                        // 5. Reset grid height after animation
                        grid.addEventListener('transitionend', () => {
                            grid.style.transition = '';
                            grid.style.height = '';
                        }, { once: true });
                    });
                }
            });
        });
    }

    // --- NEW: Interactive Sidebar Logic ---
    const sidebarWrapper = document.querySelector('.sidebar-content-wrapper');
    const sidebarNavLinks = document.querySelectorAll('.sidebar-navigator .navigator-list a');
    const sidebarCards = document.querySelectorAll('.sidebar-content-wrapper .tool-card');

    if (sidebarWrapper && sidebarNavLinks.length > 0 && sidebarCards.length > 0) {
        // 1. Smooth scrolling on click
        sidebarNavLinks.forEach(link => {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                const targetId = this.getAttribute('href');
                const targetElement = document.querySelector(targetId);
                if (targetElement) {
                    targetElement.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            });
        });

        // 2. Intersection Observer to highlight active link
        const sidebarObserverOptions = {
            root: sidebarWrapper,
            rootMargin: '0px 0px -50% 0px',
            threshold: 0.1
        };

        const sidebarObserver = new IntersectionObserver((entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    // Add the animation class to the card
                    entry.target.classList.add('is-visible');

                    // Highlight the corresponding nav link
                    const targetId = `#${entry.target.id}`;
                    const correspondingLink = document.querySelector(`.sidebar-navigator a[href="${targetId}"]`);
                    if (correspondingLink) {
                        sidebarNavLinks.forEach(link => link.classList.remove('active'));
                        correspondingLink.classList.add('active');
                    }
                }
            });
        }, sidebarObserverOptions);

        sidebarCards.forEach(card => sidebarObserver.observe(card));
    }

    // --- Consolidated Animations & Interactive Elements ---

    /* ===== Utility ===== */
    const $ = (sel, root=document) => root.querySelector(sel);
    const $$ = (sel, root=document) => Array.from(root.querySelectorAll(sel));

    /* ===== Loader ===== */
    window.addEventListener('load', () => {
      setTimeout(()=> $('#loader')?.classList.add('hidden'), 600);
    });

});

// --- NEW: Toast Notification System ---
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    let iconClass = 'fas fa-info-circle';
    if (type === 'success') iconClass = 'fas fa-check-circle';
    if (type === 'danger') iconClass = 'fas fa-exclamation-triangle';

    toast.innerHTML = `<i class="${iconClass}"></i><span>${message}</span>`;
    container.appendChild(toast);

    // Trigger the fade-out animation which also removes the element
    toast.addEventListener('animationend', (e) => {
        if (e.animationName === 'fadeOutToast') {
            toast.remove();
        }
    });
}

// --- NEW: Interactive Guide Feature ---
function highlightToolCard(targetId) {
    const modal = document.getElementById('guide-modal');
    const targetCard = document.getElementById(targetId);

    if (!targetCard) {
        console.error(`Highlight target not found: ${targetId}`);
        return;
    }

    // Close the modal
    if (modal) {
        modal.classList.remove('active');
    }

    // Scroll to the card and apply highlight
    targetCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
    targetCard.classList.add('highlight-pulse');
    targetCard.addEventListener('animationend', () => { targetCard.classList.remove('highlight-pulse'); }, { once: true });
}

// --- NEW: Secure Chain of Custody Verification ---
function verifyChainOfCustody(showSuccessToast = false) {
    if (chainOfCustody.length === 0) {
        if (showSuccessToast) showToast('Chain is empty, nothing to verify.', 'info');
        return;
    }
    let isValid = true;
    // The chain is stored newest-first, so we iterate backwards to check from oldest to newest.
    for (let i = chainOfCustody.length - 1; i >= 0; i--) {
        const entry = chainOfCustody[i];
        
        // Determine the previous hash. For the oldest entry (the genesis block), it's a known string of zeros.
        const expectedPreviousHash = (i === chainOfCustody.length - 1) 
            ? '0'.repeat(64) 
            : chainOfCustody[i + 1].hash;

        if (entry.previousHash !== expectedPreviousHash) {
            isValid = false;
            break;
        }

        // Recalculate the current entry's hash to see if its data has been tampered with.
        const entryString = `${entry.id}|${entry.action}|${entry.target}|${entry.status}|${entry.type}|${entry.details}|${entry.timestamp}|${entry.previousHash}`;
        const recalculatedHash = CryptoJS.SHA256(entryString).toString();

        if (entry.hash !== recalculatedHash) {
            isValid = false;
            break;
        }
    }

    if (isValid) {
        if (showSuccessToast) showToast('Chain of Custody integrity verified successfully!', 'success');
    } else {
        showToast('CRITICAL: Chain of Custody has been broken or tampered with!', 'danger');
    }
}

function resetSession() {
    analysisResults = { sessionId: `PHANIX-${Math.floor(1000 + Math.random() * 9000)}` };
    chainOfCustody = [];
    chatHistory = [{
        role: "user",
        parts: [{ text: "You are a world-class digital forensics expert and AI assistant called P.H.A.N.I.X. Your purpose is to assist users in analyzing digital evidence. Be concise, accurate, and provide actionable advice. When asked to summarize, use the provided analysis data. Do not mention you are a language model." }]
    }, {
        role: "model",
        parts: [{ text: "Understood. I am the P.H.A.N.I.X AI, ready to assist with forensic analysis." }]
    }];
    document.getElementById('case-name').value = '';
    document.getElementById('case-type').value = '';
    document.getElementById('case-notes-textarea').value = '';

    // Apply default user settings from localStorage to both settings and report cards
    const defaultInvestigator = localStorage.getItem('defaultInvestigatorName') || '';
    const defaultOrg = localStorage.getItem('defaultOrgName') || '';
    document.getElementById('investigator-name').value = defaultInvestigator;
    document.getElementById('org-name').value = defaultOrg;
    document.getElementById('setting-investigator-name').value = defaultInvestigator;
    document.getElementById('setting-org-name').value = defaultOrg;

    addCoCEntry('Session Started', 'System', 'low', `New investigation session initialized.`);
}

function clearAllSettings() {
    if (confirm('Are you sure you want to clear all saved settings? This will remove your saved theme and default investigator info. This action cannot be undone.')) {
        localStorage.removeItem('theme');
        localStorage.removeItem('defaultInvestigatorName');
        localStorage.removeItem('defaultOrgName');
        alert('All saved settings have been cleared. The page will now reload to apply changes.');
        location.reload();
    }
}

function clearToolState(cardId) {
    const card = document.getElementById(cardId);
    if (!card) return;

    // Reset file inputs
    card.querySelectorAll('input[type="file"]').forEach(input => {
        input.value = '';
    });

    // Reset text/password inputs and textareas
    card.querySelectorAll('input[type="password"], textarea').forEach(input => {
        input.value = '';
    });

    // --- NEW: Clear AI First Look div ---
    const aiLookDiv = document.getElementById(`${cardId.replace('-card', '')}-ai-look`);
    if (aiLookDiv) {
        aiLookDiv.style.display = 'none';
        aiLookDiv.innerHTML = '';
    }

    // Reset output divs to their default text
    const output = card.querySelector('.output, #network-output');
    if (output) {
        const defaultTexts = {
            'integrity-card': 'Select a file and click "Full Scan".',
            'comparison-card': 'Select two files and click "Compare Files".',
            'metadata-card': 'Select a file and click "Analyze Metadata".',
            'stego-card': 'Select an image and click "Analyze Bit Plane".',
            'password-card': 'Enter a password and click "Full Analysis".',
            'network-card': '' // Use CSS placeholder
        };
        output.innerHTML = defaultTexts[cardId] || 'Output will appear here.';
    }

    // Hide and destroy charts
    card.querySelectorAll('canvas').forEach(canvas => {
        destroyChart(canvas.id);
        canvas.style.display = 'none';
    });

    // Hide AI buttons
    card.querySelectorAll('#meta-ai-btn, #net-ai-btn').forEach(btn => {
        btn.style.display = 'none';
    });

    // Specific resets for special tools
    if (cardId === 'integrity-card') {
        const hexViewer = document.getElementById('hex-viewer-output');
        if (hexViewer) {
            hexViewer.innerHTML = '';
            hexViewer.style.display = 'none';
        }
        const carveBtn = document.getElementById('find-carve-btn');
        const carveOutput = document.getElementById('carve-output');
        if (carveBtn) carveBtn.disabled = true;
        if (carveOutput) {
            carveOutput.style.display = 'none';
            carveOutput.innerHTML = '';
        }
        currentFileForHexView = null;
    }
    if (cardId === 'metadata-card') {
        const mapContainer = document.getElementById('map-container');
        if (mapContainer) mapContainer.style.display = 'none';
        if (mapInstance) {
            mapInstance.remove();
            mapInstance = null;
        }
    }
    if (cardId === 'password-card') {
        const scoreData = calculatePasswordScore('');
        renderPasswordStrengthBar(scoreData);
    }
}

function destroyChart(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (canvas && canvas.chart) {
        canvas.chart.destroy();
        canvas.chart = null;
    }
}

async function runAnalysis(cardId, analysisFn) {
    const loader = document.querySelector(`#${cardId} .card-loader`);
    const buttons = document.querySelectorAll(`#${cardId} button`);
    loader.classList.add('active');
    buttons.forEach(b => b.disabled = true);
    
    try {
        await new Promise(res => setTimeout(res, 50));
        await analysisFn();
        // --- NEW: Trigger AI First Look ---
        getAiFirstLook(cardId); // Fire-and-forget, runs in background
    } catch (error) {
        console.error(`Analysis failed for ${cardId}:`, error);
        const output = document.querySelector(`#${cardId} .output`);
        if(output) output.innerHTML = `<span class="danger">An unexpected error occurred: ${error.message}</span>`;
    } finally {
        loader.classList.remove('active');
        buttons.forEach(b => b.disabled = false);
    }
}

// --- NEW: AI First Look Feature ---
async function getAiFirstLook(cardId) {
    const aiLookDiv = document.getElementById(`${cardId.replace('-card', '')}-ai-look`);
    if (!aiLookDiv) return;

    let prompt = '';
    let contextData = null;

    switch (cardId) {
        case 'integrity-card':
            contextData = analysisResults.fileHash;
            if (!contextData) return;
            prompt = `Based on this file integrity analysis, provide a single, impactful sentence for a forensic expert. Focus on the relationship between file type, entropy, and threat status. Data: ${JSON.stringify(contextData)}`;
            break;
        case 'metadata-card':
            contextData = analysisResults.metadata;
            if (!contextData || !contextData.keyFindings || Object.keys(contextData.keyFindings).length === 0) return;
            prompt = `Based on these key metadata findings, provide a single, impactful sentence for a forensic expert highlighting the most critical piece of evidence. Data: ${JSON.stringify(contextData.keyFindings)}`;
            break;
        case 'network-card':
            contextData = analysisResults.network;
            if (!contextData || !contextData.threats || contextData.threats.length === 0) return;
            // Find the highest risk threat
            const highestRiskThreat = contextData.threats[0]; // Already sorted by risk
            prompt = `Based on this primary correlated network threat, provide a single, impactful sentence for a cybersecurity analyst. Threat: ${JSON.stringify(highestRiskThreat)}`;
            break;
        default:
            return; // Not implemented for this card
    }

    aiLookDiv.style.display = 'block';
    aiLookDiv.innerHTML = `
        <div class="ai-header"><i class="fas fa-brain"></i> AI First Look</div>
        <div class="ai-content loading-text">Analyzing context...</div>
    `;

    const aiResponse = await callGemini(prompt);
    
    if (aiResponse && !aiResponse.startsWith('Error:')) { aiLookDiv.querySelector('.ai-content').innerHTML = sanitizeHTML(aiResponse); } 
    else { aiLookDiv.style.display = 'none'; } // Hide on error to not clutter the UI
}

function toggleHexViewer(event) {
    event.preventDefault();
    const hexViewer = document.getElementById('hex-viewer-output');
    const link = event.target;
    if (!hexViewer) return;
    const isVisible = hexViewer.style.display !== 'none';
    hexViewer.style.display = isVisible ? 'none' : 'block'; link.textContent = isVisible ? 'Show Raw Hex View' : 'Hide Raw Hex View'; if (!isVisible) hexViewer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}
document.addEventListener('click', e => { if (e.target.matches('.show-more-link')) toggleHexViewer(e); });


function copyToClipboard(text, buttonElement) {
    navigator.clipboard.writeText(text).then(() => {
        const originalHTML = buttonElement.innerHTML;
        const isIconButton = buttonElement.classList.contains('copy-btn');

        if (isIconButton) {
            buttonElement.innerHTML = `<i class="fas fa-check"></i>`;
        } else {
            buttonElement.innerHTML = `<i class="fas fa-check"></i> Copied!`;
        }
        
        buttonElement.disabled = true;
        showToast('Copied to clipboard!', 'success');

        setTimeout(() => {
            buttonElement.innerHTML = originalHTML;
            buttonElement.disabled = false;
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy text: ', err);
        showToast('Failed to copy text to clipboard.', 'danger');
    });
}

function hexToRgb(hex) {
    if (!hex) return null;
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result ? {
        r: parseInt(result[1], 16),
        g: parseInt(result[2], 16),
        b: parseInt(result[3], 16)
    } : null;
}

// Helper function to get theme colors for charts
function getChartColors() {
    const style = getComputedStyle(document.body);
    return {
        primaryText: style.getPropertyValue('--text-primary').trim(),
        secondaryText: style.getPropertyValue('--text-secondary').trim(),
        borderColor: style.getPropertyValue('--border-color').trim(),
        primaryBg: style.getPropertyValue('--primary-bg').trim()
    };
}

// --- GEMINI API INTEGRATION ---
async function callGemini(prompt) {
    // The API call is now proxied through our own backend to protect the API key.
    const apiUrl = '/api/gemini';
    
    chatHistory.push({ role: "user", parts: [{ text: prompt }] });

    const payload = { contents: chatHistory };

    try {
        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const errorResult = await response.json().catch(() => ({ error: 'Could not parse error response from server.' }));
            console.error("Backend proxy error:", errorResult);
            if (response.status === 500 && errorResult.error && errorResult.error.includes('API key is not configured')) {
                 return "Error: The backend server is running, but the GEMINI_API_KEY is missing in the .env file on the server. Please configure it.";
            }
            throw new Error(`Backend proxy failed with status: ${response.status}. ${errorResult.error || ''}`);
        }

        const result = await response.json();
        
        if (result.candidates && result.candidates.length > 0 &&
            result.candidates[0].content && result.candidates[0].content.parts &&
            result.candidates[0].content.parts.length > 0) {
            const text = result.candidates[0].content.parts[0].text;
            chatHistory.push({ role: "model", parts: [{ text: text }] });
            return text;
        } else if (result.error) {
            const errorMessage = result.error.message || JSON.stringify(result.error);
            console.error("API returned an error:", errorMessage);
            return `Error from AI Service: ${sanitizeHTML(errorMessage)}`;
        } else {
            console.error("Unexpected API response structure:", result);
            return "Error: Received an invalid response from the AI. Please check the console.";
        }
    } catch (error) {
        console.error("Error calling backend proxy:", error);
        return `Error: Could not communicate with the local backend server. Is it running? Details: ${sanitizeHTML(error.message)}`;
    }
}


// --- AI CHATBOT IMPLEMENTATION ---
function quickAction(message) {
     document.getElementById('ai-chat-input').value = message;
    sendChatMessage();
}

function addAiSummaryToReport() {
    if (lastAiResponse) {
        aiSummaryForReport = lastAiResponse;
        alert("AI summary has been staged and will be added to the Executive Summary in the next PDF report.");
    } else {
        alert("No AI summary is available. Please ask the AI to summarize the findings first.");
    }
}

async function sendChatMessage() {
    const input = document.getElementById('ai-chat-input');
    const sendBtn = document.getElementById('ai-chat-send-btn');
    const message = input.value.trim();
    if (!message) return;

    appendChatMessage(message, 'user');
    input.value = '';
    input.disabled = true;
    sendBtn.disabled = true;
    sendBtn.innerHTML = `<div class="loading-spinner" style="width: 1em; height: 1em; border-width: 2px;"></div>`;

    let prompt = message;
    if (message.toLowerCase().includes('summarize') || message.toLowerCase().includes('suggest')) {
        prompt += `\n\nHere is the current analysis context in JSON format:\n${JSON.stringify(analysisResults)}`;
    }
    
    const aiResponse = await callGemini(prompt);
    lastAiResponse = aiResponse; 
    appendChatMessage(aiResponse, 'ai');

    input.disabled = false;
    sendBtn.disabled = false;
    sendBtn.innerHTML = `<i class="fas fa-paper-plane"></i>`;
}

function appendChatMessage(message, sender) {
    const chatWindow = document.getElementById('ai-chat-window');
    const messageDiv = document.createElement('div');
    messageDiv.className = `chat-message ${sender}-message`;
    // Sanitize the message to prevent XSS, then replace newlines with <br> for formatting.
    messageDiv.innerHTML = sanitizeHTML(message).replace(/\n/g, '<br>'); 
    chatWindow.appendChild(messageDiv);
    chatWindow.scrollTop = chatWindow.scrollHeight;
}

// --- TOOL FUNCTIONS ---

function generateHash() {
    return new Promise((resolve, reject) => {
        const fileInput = document.getElementById('file-upload');
        const output = document.getElementById('hash-output');
        const progressBar = document.querySelector('#integrity-card .progress-bar-inner');
        progressBar.style.width = '0%';

        if (!fileInput.files[0]) {
            output.innerHTML = '<span class="danger">Please select a file first.</span>';
            reject(new Error('No file selected.'));
            return;
        }
        const file = fileInput.files[0];
        currentFileForHexView = file;
        addCoCEntry('Evidence Acquired', file.name, 'low', `File staged for integrity analysis. Size: ${(file.size / 1024).toFixed(2)} KB`);
        document.getElementById('find-carve-btn').disabled = false;

        // --- NEW: Web Worker for background processing ---
        const workerCode = `
            self.importScripts('https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js');

            function getFileType(bytes) {
                const signatures = { "FFD8FFE0": "JPEG image", "89504E47": "PNG image", "47494638": "GIF image", "25504446": "PDF document", "504B0304": "ZIP archive", "4D5A": "Windows PE file (EXE/DLL)" };
                const hex = Array.from(bytes.slice(0, 4)).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join('');
                for (const sig in signatures) { if (hex.startsWith(sig)) return signatures[sig]; }
                return "Unknown / Generic data";
            }

            function calculateEntropy(data) {
                if (data.length === 0) return 0;
                const map = {};
                for (const byte of data) { map[byte] = (map[byte] || 0) + 1; }
                let entropy = 0;
                const len = data.length;
                for (const byte in map) { const p = map[byte] / len; entropy -= p * Math.log2(p); }
                return entropy;
            }

            self.onmessage = async (e) => {
                const { file, threatDatabase } = e.data;
                const chunkSize = 1024 * 1024 * 4;
                const sha256Hasher = CryptoJS.algo.SHA256.create();
                const sha1Hasher = CryptoJS.algo.SHA1.create();
                const md5Hasher = CryptoJS.algo.MD5.create();
                const frequencies = new Array(256).fill(0);
                let totalBytesProcessed = 0;
                const plotBlockSize = Math.max(256, Math.floor(file.size / 512));
                let blockEntropies = [];
                let currentPlotBlock = new Uint8Array(plotBlockSize);
                let currentPlotBlockIndex = 0;

                const firstBytes = new Uint8Array(await file.slice(0, 4).arrayBuffer());
                const fileType = getFileType(firstBytes);
                const hexViewBytes = new Uint8Array(await file.slice(0, 512).arrayBuffer());

                for (let offset = 0; offset < file.size; offset += chunkSize) {
                    const chunkBuffer = await file.slice(offset, offset + chunkSize).arrayBuffer();
                    const chunkBytes = new Uint8Array(chunkBuffer);
                    const wordArray = CryptoJS.lib.WordArray.create(chunkBytes);
                    sha256Hasher.update(wordArray);
                    sha1Hasher.update(wordArray);
                    md5Hasher.update(wordArray);
                    for (const byte of chunkBytes) {
                        frequencies[byte]++;
                        currentPlotBlock[currentPlotBlockIndex++] = byte;
                        if (currentPlotBlockIndex === plotBlockSize) {
                            blockEntropies.push(calculateEntropy(currentPlotBlock));
                            currentPlotBlockIndex = 0;
                        }
                    }
                    totalBytesProcessed += chunkBytes.length;
                    self.postMessage({ type: 'progress', value: (totalBytesProcessed / file.size) * 100 });
                }

                if (currentPlotBlockIndex > 0) {
                    blockEntropies.push(calculateEntropy(currentPlotBlock.slice(0, currentPlotBlockIndex)));
                }

                const hashes = {
                    sha256: sha256Hasher.finalize().toString(),
                    sha1: sha1Hasher.finalize().toString(),
                    md5: md5Hasher.finalize().toString()
                };

                let entropy = 0;
                for (const freq of frequencies) { if (freq > 0) { const p = freq / file.size; entropy -= p * Math.log2(p); } }

                const threatInfo = threatDatabase[hashes.sha256];
                const isMalicious = !!threatInfo;

                self.postMessage({ type: 'result', data: { file, hashes, entropy, frequencies, blockEntropies, plotBlockSize, fileType, hexViewBytes, isMalicious, threatInfo } });
                self.close();
            };
        `;

        const blob = new Blob([workerCode], { type: 'application/javascript' });
        const worker = new Worker(URL.createObjectURL(blob));

        worker.onmessage = (e) => {
            const { type, data, value } = e.data;
            if (type === 'progress') {
                progressBar.style.width = `${value}%`;
            } else if (type === 'result') {
                progressBar.style.width = '100%';
                const { file, hashes, entropy, frequencies, blockEntropies, plotBlockSize, fileType, hexViewBytes, isMalicious, threatInfo } = data;
                
                let resultHTML = `--- File Integrity & Threat Report ---\nFilename:      ${sanitizeHTML(file.name)}\nFile Size:     ${(file.size / 1024).toFixed(2)} KB\nIdentified Type: ${sanitizeHTML(fileType)}\n\n--- Cryptographic Hashes ---\n`;
                
                resultHTML += `MD5:    ${hashes.md5}<button class="copy-btn" title="Copy MD5" onclick="copyToClipboard('${hashes.md5}', this)"><i class="fas fa-copy"></i></button>\n`;
                resultHTML += `SHA-1:  ${hashes.sha1}<button class="copy-btn" title="Copy SHA-1" onclick="copyToClipboard('${hashes.sha1}', this)"><i class="fas fa-copy"></i></button>\n`;
                resultHTML += `SHA-256: <span class="info">${hashes.sha256}</span><button class="copy-btn" title="Copy SHA-256" onclick="copyToClipboard('${hashes.sha256}', this)"><i class="fas fa-copy"></i></button>\n\n`;

                resultHTML += `--- Threat Intelligence Analysis ---\n`;
                resultHTML += isMalicious ? `Status: <span class="danger">KNOWN THREAT DETECTED</span>\nMatch:  ${sanitizeHTML(threatInfo)}\n\n` : `Status: <span class="success">No known threats found in database.</span>\n\n`;

                let entropyAssessment, entropyColor, entropyInterpretation;
                const isCompressedType = fileType.includes('JPEG') || fileType.includes('PNG') || fileType.includes('GIF') || fileType.includes('ZIP');
                if (isCompressedType) {
                    if (entropy > 7.0) { entropyAssessment = 'Normal (Compressed)'; entropyColor = 'success'; } else { entropyAssessment = 'Moderate'; entropyColor = 'warning'; }
                    entropyInterpretation = `High entropy is expected for compressed file types like ${sanitizeHTML(fileType)}.`;
                } else {
                    if (entropy > 7.5) { entropyAssessment = 'HIGH'; entropyColor = 'danger'; } else if (entropy < 6.0) { entropyAssessment = 'LOW'; entropyColor = 'warning'; } else { entropyAssessment = 'Normal'; entropyColor = 'success'; }
                    entropyInterpretation = `An entropy level of '${entropyAssessment}' for a ${sanitizeHTML(fileType)} can be significant. High entropy may indicate encryption or packing.`;
                }
                resultHTML += `--- Entropy Analysis ---\nShannon Entropy (Overall): ${entropy.toFixed(4)} / 8.0\nAssessment:              <span class="${entropyColor}">${entropyAssessment}</span>\n\n<div class="interpretation"><strong>Interpretation:</strong> ${entropyInterpretation} <a href="#" onclick="toggleHexViewer(event)" class="show-more-link">Show Raw Hex View</a></div>`;

                output.innerHTML = resultHTML.replace(/<button class="copy-btn".*?<\/button>/g, ''); // Remove buttons before inserting
                renderHexView(hexViewBytes);
                renderEntropyChart(frequencies);
                renderEntropyPlotChart(blockEntropies, plotBlockSize);
                const maxBlockEntropy = Math.max(...blockEntropies);
                const minBlockEntropy = Math.min(...blockEntropies);

                analysisResults.fileHash = { fileName: file.name, hashes, isMalicious, threatName: threatInfo || 'N/A', entropy, fileType, fileSize: file.size, blockEntropy: { min: minBlockEntropy, max: maxBlockEntropy, average: blockEntropies.reduce((a, b) => a + b, 0) / blockEntropies.length }, entropyAssessment };
                addCoCEntry('File Threat Scan', file.name, isMalicious ? 'high' : 'low', `Scan complete. Threat status: ${isMalicious ? 'Positive' : 'Negative'}. Entropy: ${entropy.toFixed(2)}`, 'auto');
                
                // Now that the HTML is in the DOM, re-insert buttons and attach listeners
                output.innerHTML = resultHTML;
                output.querySelectorAll('.copy-btn').forEach(btn => {
                    btn.addEventListener('click', () => {
                        copyToClipboard(btn.dataset.copy, btn);
                    });
                });
                worker.terminate();
                URL.revokeObjectURL(blob);
                resolve();
            }
        };

        worker.onerror = (err) => {
            output.innerHTML = `<span class="danger">An error occurred in the analysis worker: ${err.message}</span>`;
            worker.terminate();
            URL.revokeObjectURL(blob);
            reject(err);
        };

        worker.postMessage({ file, threatDatabase });
    });
}

function renderEntropyChart(frequencies) {
    const chartCanvas = document.getElementById('entropy-chart');
    chartCanvas.style.display = 'block';
    destroyChart('entropy-chart');
    const style = getComputedStyle(document.body);
    const chartColors = getChartColors();

    const ctx = chartCanvas.getContext('2d');
    chartCanvas.chart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: Array.from({length: 256}, (_, i) => i.toString(16).padStart(2, '0')),
            datasets: [{
                label: 'Byte Frequency Distribution',
                data: frequencies,
                backgroundColor: `rgba(${style.getPropertyValue('--accent-primary-rgb').trim()}, 0.5)`,
                borderColor: style.getPropertyValue('--accent-primary').trim(),
                borderWidth: 1,
                barPercentage: 1.0,
                categoryPercentage: 1.0
            }]
        },
        options: {
            plugins: {
                legend: { display: false },
                title: { display: true, text: 'Byte Frequency Distribution', color: chartColors.primaryText }
            },
            scales: {
                x: { display: false },
                y: { beginAtZero: true, ticks: { color: chartColors.secondaryText }, grid: { color: chartColors.borderColor } }
            }
        }
    });
}

function renderEntropyPlotChart(blockEntropies, blockSize) {
    const chartCanvas = document.getElementById('byte-plot-chart');
    chartCanvas.style.display = 'block';
    destroyChart('byte-plot-chart');
    const style = getComputedStyle(document.body);
    const chartColors = getChartColors();

    const ctx = chartCanvas.getContext('2d');
    chartCanvas.chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: blockEntropies.map((_, i) => i * blockSize),
            datasets: [{
                label: 'Block Entropy',
                data: blockEntropies,
                borderColor: style.getPropertyValue('--warning').trim(),
                backgroundColor: `rgba(${hexToRgb(style.getPropertyValue('--warning').trim()).r}, ${hexToRgb(style.getPropertyValue('--warning').trim()).g}, ${hexToRgb(style.getPropertyValue('--warning').trim()).b}, 0.2)`,
                borderWidth: 1,
                pointRadius: 0,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            plugins: {
                legend: { display: false },
                title: { display: true, text: `Entropy Plot (Block Size: ${blockSize} bytes)`, color: chartColors.primaryText }
            },
            scales: {
                x: {
                    display: true,
                    title: { display: true, text: 'File Offset (bytes)', color: chartColors.secondaryText},
                    ticks: { color: chartColors.secondaryText },
                    grid: { color: chartColors.borderColor }
                },
                y: {
                    beginAtZero: true,
                    max: 8,
                    title: { display: true, text: 'Entropy (bits)', color: chartColors.secondaryText},
                    ticks: { color: chartColors.secondaryText },
                    grid: { color: chartColors.borderColor }
                }
            }
        }
    });
}

function calculateEntropy(data) {
    if (data.length === 0) return 0;
    const map = {};
    for (const byte of data) { map[byte] = (map[byte] || 0) + 1; }
    let entropy = 0;
    const len = data.length;
    for (const byte in map) {
        const p = map[byte] / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

function getFileType(bytes) {
    const signatures = {
        "FFD8FFE0": "JPEG image", "89504E47": "PNG image", "47494638": "GIF image",
        "25504446": "PDF document", "504B0304": "ZIP archive", "4D5A": "Windows PE file (EXE/DLL)"
    };
    const hex = Array.from(bytes.slice(0, 4)).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join('');
    for (const sig in signatures) {
        if (hex.startsWith(sig)) return signatures[sig];
    }
    return "Unknown / Generic data";
}

// --- FILE CARVING LOGIC (IMPROVED) ---

/**
 * Carving strategy: Find End of File by searching for a trailer signature.
 * @param {File} file The file object to search within.
 * @param {number} startOffset The offset to start searching from.
 * @param {object} options Options, including { trailer: 'hexstring', findLast: boolean }.
 * @returns {Promise<number>} The calculated end offset of the file, or -1 if not found.
 */
async function findEndByTrailer(file, startOffset, options) {
    const trailerBytes = options.trailer.match(/.{1,2}/g).map(byte => parseInt(byte, 16));
    const trailerLen = trailerBytes.length;
    const searchChunkSize = 1024 * 512; // 512KB
    let lastFoundOffset = -1;

    for (let offset = startOffset; offset < file.size; offset += searchChunkSize) {
        const readStart = offset > startOffset ? offset - trailerLen : offset;
        const chunk = await file.slice(readStart, readStart + searchChunkSize + trailerLen).arrayBuffer();
        const bytes = new Uint8Array(chunk);

        for (let i = 0; i < bytes.length - trailerLen + 1; i++) {
            let match = true;
            for (let j = 0; j < trailerLen; j++) {
                if (bytes[i + j] !== trailerBytes[j]) { match = false; break; }
            }
            if (match) {
                lastFoundOffset = readStart + i + trailerLen;
                if (!options.findLast) return lastFoundOffset;
            }
        }
    }

    if (lastFoundOffset !== -1 && options.trailer === '2525454f46') { // %%EOF for PDF
        const checkBytes = new Uint8Array(await file.slice(lastFoundOffset, lastFoundOffset + 2).arrayBuffer());
        if (checkBytes.length > 0 && checkBytes[0] === 0x0A) lastFoundOffset++; // LF
        if (checkBytes.length > 1 && checkBytes[0] === 0x0D && checkBytes[1] === 0x0A) lastFoundOffset++; // CRLF
    }
    return lastFoundOffset;
}

/**
 * Carving strategy: Find End of Central Directory record for ZIP files.
 * This is more reliable than a simple trailer search.
 * @param {File} file The file object to search within.
 * @param {number} startOffset The offset where the ZIP header was found.
 * @returns {Promise<number>} The calculated end offset of the file, or -1 if not found.
 */
async function findEndZip(file, startOffset, options) {
    const eocdSig = [0x50, 0x4b, 0x05, 0x06];
    const searchChunkSize = 65535 + 22; // Max ZIP comment size + EOCD record size
    const readStart = Math.max(startOffset, file.size - searchChunkSize);
    const chunk = await file.slice(readStart).arrayBuffer();
    const bytes = new Uint8Array(chunk);

    for (let i = bytes.length - 22; i >= 0; i--) {
        if (bytes[i] === eocdSig[0] && bytes[i+1] === eocdSig[1] && bytes[i+2] === eocdSig[2] && bytes[i+3] === eocdSig[3]) {
            const commentLength = bytes[i + 20] | (bytes[i + 21] << 8);
            return readStart + i + 22 + commentLength;
        }
    }
    return -1; // Not found
}

const fileSignaturesForCarving = {
    'JPEG': { hex: 'ffd8ffe0', ext: 'jpg', findEnd: findEndByTrailer, options: { trailer: 'ffd9' } },
    'JPEG_EXIF': { hex: 'ffd8ffe1', ext: 'jpg', findEnd: findEndByTrailer, options: { trailer: 'ffd9' } },
    'PNG': { hex: '89504e47', ext: 'png', findEnd: findEndByTrailer, options: { trailer: '49454e44ae426082' } },
    'GIF': { hex: '47494638', ext: 'gif', findEnd: findEndByTrailer, options: { trailer: '3b' } }, // Covers GIF87a and GIF89a
    'PDF': { hex: '25504446', ext: 'pdf', findEnd: findEndByTrailer, options: { trailer: '2525454f46', findLast: true } },
    'ZIP-based (ZIP, DOCX, etc.)': { hex: '504b0304', ext: 'zip', findEnd: findEndZip },
};

async function findAndCarveSignatures() {
    const output = document.getElementById('carve-output');
    const file = currentFileForHexView;
    if (!file) {
        output.style.display = 'block';
        output.innerHTML = '<span class="danger">Please run a "Full Scan" on a file first.</span>';
        return;
    }

    addCoCEntry('Signature Scan', file.name, 'medium', 'Initiated scan for embedded file signatures.');
    output.style.display = 'block';
    output.innerHTML = 'Scanning for known file headers... This may take a moment for large files.';

    const signatures = fileSignaturesForCarving;
    const sigBytes = {};
    for (const key in signatures) {
        sigBytes[key] = signatures[key].hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16));
    }

    const chunkSize = 1024 * 1024; // 1MB
    const maxSigLen = 8;
    let foundHeaders = [];

    for (let offset = 0; offset < file.size; offset += chunkSize) {
        const chunk = await file.slice(offset, offset + chunkSize + maxSigLen).arrayBuffer();
        const bytes = new Uint8Array(chunk);
        
        for (let i = 0; i < bytes.length; i++) {
            for (const key in sigBytes) {
                const sig = sigBytes[key];
                if (i + sig.length > bytes.length) continue;
                let match = true;
                for (let j = 0; j < sig.length; j++) {
                    if (bytes[i + j] !== sig[j]) { match = false; break; }
                }
                if (match && !foundHeaders.some(h => h.offset === (offset + i))) { // Prevent adding duplicates for same offset
                    foundHeaders.push({ type: key, offset: offset + i });
                    i += sig.length - 1;
                }
            }
        }
    }

    if (foundHeaders.length === 0) {
        output.innerHTML = '<span class="success">No known file signatures found within the file.</span>';
        return;
    }

    let resultHTML = `Found ${foundHeaders.length} potential embedded file(s):\n\n`;
    foundHeaders.forEach(header => {
        const sigInfo = signatures[header.type];
        resultHTML += `<strong>- ${header.type.replace('_', ' ')}</strong> found at offset <span class="info">0x${header.offset.toString(16)}</span>\n`;
        resultHTML += `<button class="secondary" style="padding: 0.2rem 0.5rem; font-size: 0.8rem; margin: 0.2rem 0 0.8rem 1rem;" onclick="carveFile(${header.offset}, '${header.type}')">Carve File (.${sigInfo.ext})</button>\n`;
    });
    
    resultHTML += `<div class="interpretation" style="margin-top: 1rem;"><strong>Note:</strong> Carving attempts to find the end-of-file marker. If not found, it will prompt for a length. The resulting file may contain extra data.</div>`;
    output.innerHTML = resultHTML;
}

async function carveFile(startOffset, type) {
    const file = currentFileForHexView;
    const sigInfo = fileSignaturesForCarving[type];
    if (!file || !sigInfo) { alert('Error: Could not find file or signature info to carve.'); return; }

    let endOffset = -1;
    if (sigInfo.findEnd) {
        endOffset = await sigInfo.findEnd(file, startOffset, sigInfo.options);
    }

    if (endOffset === -1) {
        const userInput = prompt(`Could not automatically determine the size of the ${type} file. Please specify a length in bytes to carve from the start offset (0x${startOffset.toString(16)}).`, 1024 * 1024 * 2); // Default 2MB
        if (userInput === null) return;
        const length = parseInt(userInput);
        if (isNaN(length) || length <= 0) { alert('Invalid length provided.'); return; }
        endOffset = startOffset + length;
    }

    if (endOffset > file.size) endOffset = file.size;

    const carvedSize = endOffset - startOffset;
    const blob = file.slice(startOffset, endOffset);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `carved_${type.split(' ')[0]}_at_0x${startOffset.toString(16)}.${sigInfo.ext}`;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);

    addCoCEntry('File Carved', a.download, 'high', `Carved ${type} file of size ${(carvedSize/1024).toFixed(2)} KB from ${file.name} at offset 0x${startOffset.toString(16)}.`);
    alert(`Successfully carved ${a.download} (${(carvedSize/1024).toFixed(2)} KB).`);
}

function renderHexView(bytes) {
    const viewer = document.getElementById('hex-viewer-output');
    if (!viewer) return;

    let html = '';
    const bytesLength = bytes.length;

    for (let i = 0; i < bytesLength; i += 16) {
        const slice = bytes.slice(i, i + 16);
        
        // 1. Offset
        const offset = i.toString(16).padStart(8, '0');
        html += `<div class="row"><span class="hex-offset">${offset}</span>`;

        // 2. Hex Bytes
        let hexString = '';
        for (let j = 0; j < 16; j++) {
            if (j < slice.length) {
                hexString += `<span class="hex-byte">${slice[j].toString(16).padStart(2, '0')}</span>`;
            } else {
                hexString += '<span class="hex-byte">  </span>'; // Padding for shorter last line
            }
            if (j === 7) hexString += ' '; // Space in the middle
        }
        html += hexString;

        // 3. ASCII representation
        let asciiString = ' <span class="hex-ascii">';
        for (let j = 0; j < slice.length; j++) {
            const charCode = slice[j];
            const char = (charCode >= 32 && charCode <= 126) ? String.fromCharCode(charCode) : '.';
            asciiString += char.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        }
        asciiString += '</span>';
        html += asciiString;

        html += '</div>';
    }
    viewer.innerHTML = html || '<span>File is empty or could not be read.</span>';
}

function compareFiles() {
    return new Promise((resolve, reject) => {
        const fileInput1 = document.getElementById('file-compare-1');
        const fileInput2 = document.getElementById('file-compare-2');
        const output = document.getElementById('comparison-output');
        const progressBar = document.querySelector('#comparison-card .progress-bar-inner');
        progressBar.style.width = '0%';

        if (!fileInput1.files[0] || !fileInput2.files[0]) {
            output.innerHTML = '<span class="danger">Please select two files to compare.</span>';
            reject(new Error('Two files not selected.'));
            return;
        }

        const file1 = fileInput1.files[0];
        const file2 = fileInput2.files[0];
        addCoCEntry('File Comparison', `${file1.name} vs ${file2.name}`, 'medium', 'Initiated file comparison.', 'auto');

        const workerCode = `
            self.importScripts('https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js');

            self.onmessage = async (e) => {
                const { file1, file2 } = e.data;
                const chunkSize = 1024 * 1024; // 1MB chunks

                const hashers1 = { sha256: CryptoJS.algo.SHA256.create(), sha1: CryptoJS.algo.SHA1.create(), md5: CryptoJS.algo.MD5.create() };
                const hashers2 = { sha256: CryptoJS.algo.SHA256.create(), sha1: CryptoJS.algo.SHA1.create(), md5: CryptoJS.algo.MD5.create() };

                const totalSizeToProcess = Math.max(file1.size, file2.size);
                const numDiffBlocks = 350 * 50; // Match canvas dimensions
                const diffBlocks = new Array(numDiffBlocks).fill(false);
                const bytesPerBlock = Math.max(1, Math.floor(totalSizeToProcess / numDiffBlocks));

                const firstBytes1 = new Uint8Array(await file1.slice(0, 256).arrayBuffer());
                const firstBytes2 = new Uint8Array(await file2.slice(0, 256).arrayBuffer());

                for (let offset = 0; offset < totalSizeToProcess; offset += chunkSize) {
                    const [chunkBuffer1, chunkBuffer2] = await Promise.all([
                        file1.slice(offset, offset + chunkSize).arrayBuffer(),
                        file2.slice(offset, offset + chunkSize).arrayBuffer()
                    ]);

                    const chunkBytes1 = new Uint8Array(chunkBuffer1);
                    const chunkBytes2 = new Uint8Array(chunkBuffer2);

                    hashers1.sha256.update(CryptoJS.lib.WordArray.create(chunkBytes1));
                    hashers1.sha1.update(CryptoJS.lib.WordArray.create(chunkBytes1));
                    hashers1.md5.update(CryptoJS.lib.WordArray.create(chunkBytes1));

                    hashers2.sha256.update(CryptoJS.lib.WordArray.create(chunkBytes2));
                    hashers2.sha1.update(CryptoJS.lib.WordArray.create(chunkBytes2));
                    hashers2.md5.update(CryptoJS.lib.WordArray.create(chunkBytes2));

                    const maxChunkLen = Math.max(chunkBytes1.length, chunkBytes2.length);
                    for (let i = 0; i < maxChunkLen; i++) {
                        if (chunkBytes1[i] !== chunkBytes2[i]) {
                            const blockIndex = Math.floor((offset + i) / bytesPerBlock);
                            if (blockIndex < numDiffBlocks) diffBlocks[blockIndex] = true;
                        }
                    }
                    self.postMessage({ type: 'progress', value: (Math.min(offset + chunkSize, totalSizeToProcess) / totalSizeToProcess) * 100 });
                }

                const hashes1 = { md5: hashers1.md5.finalize().toString(), sha1: hashers1.sha1.finalize().toString(), sha256: hashers1.sha256.finalize().toString() };
                const hashes2 = { md5: hashers2.md5.finalize().toString(), sha1: hashers2.sha1.finalize().toString(), sha256: hashers2.sha256.finalize().toString() };

                self.postMessage({ type: 'result', data: { file1, file2, hashes1, hashes2, diffBlocks, firstBytes1, firstBytes2 } });
                self.close();
            };
        `;

        const blob = new Blob([workerCode], { type: 'application/javascript' });
        const worker = new Worker(URL.createObjectURL(blob));

        worker.onmessage = (e) => {
            const { type, data, value } = e.data;
            if (type === 'progress') {
                progressBar.style.width = `${value}%`;
            } else if (type === 'result') {
                progressBar.style.width = '100%';
                const { file1, file2, hashes1, hashes2, diffBlocks, firstBytes1, firstBytes2 } = data;
                const sameSHA256 = hashes1.sha256 === hashes2.sha256;
                let resultHTML = sameSHA256 ? `<div class="comparison-summary summary-identical"><i class="fas fa-check-circle"></i> Files are cryptographically identical.</div>` : `<div class="comparison-summary summary-different"><i class="fas fa-times-circle"></i> Files are different.</div>`;
                resultHTML += `
                    <table class="comparison-results-table">
                        <thead><tr><th colspan="2" class="file-header">File 1: ${sanitizeHTML(file1.name)} (${(file1.size / 1024).toFixed(2)} KB)</th></tr></thead>
                        <tbody><tr><th>MD5</th><td>${hashes1.md5}</td></tr><tr><th>SHA-1</th><td>${hashes1.sha1}</td></tr><tr><th>SHA-256</th><td>${hashes1.sha256}</td></tr></tbody>
                    </table>
                    <table class="comparison-results-table">
                        <thead><tr><th colspan="2" class="file-header">File 2: ${sanitizeHTML(file2.name)} (${(file2.size / 1024).toFixed(2)} KB)</th></tr></thead>
                        <tbody><tr><th>MD5</th><td>${hashes2.md5}</td></tr><tr><th>SHA-1</th><td>${hashes2.sha1}</td></tr><tr><th>SHA-256</th><td>${hashes2.sha256}</td></tr></tbody>
                    </table>`;
                if (!sameSHA256) {
                    resultHTML += `<div class="interpretation">The visual 'Diff Map' below shows where the files differ. Red areas indicate changed blocks.</div>`;
                }
                output.innerHTML = resultHTML;
                analysisResults.comparison = { file1: { name: file1.name, size: file1.size, hashes: hashes1 }, file2: { name: file2.name, size: file2.size, hashes: hashes2 }, areIdentical: sameSHA256, firstBytes1, firstBytes2 };
                addCoCEntry('Comparison Result', `${file1.name} vs ${file2.name}`, sameSHA256 ? 'low' : 'high', sameSHA256 ? 'Files are identical.' : 'Files are different.', 'auto');
                renderDiffMap(diffBlocks, 350, 50);
                if (!sameSHA256) {
                    renderHexDiffView(firstBytes1, firstBytes2);
                }
                worker.terminate();
                URL.revokeObjectURL(blob);
                resolve();
            }
        };

        worker.onerror = (err) => {
            output.innerHTML = `<span class="danger">An error occurred in the comparison worker: ${err.message}</span>`;
            worker.terminate();
            URL.revokeObjectURL(blob);
            reject(err);
        };

        worker.postMessage({ file1, file2 });
    });
}

function renderDiffMap(diffBlocks, width, height) {
    const canvas = document.getElementById('diff-map-canvas');
    canvas.style.display = 'block';
    const ctx = canvas.getContext('2d');
    
    const blockWidth = canvas.width / width;
    const blockHeight = canvas.height / height;
    
    const diffColor = getComputedStyle(document.body).getPropertyValue('--diff-color').trim();
    const sameColor = `rgba(${getComputedStyle(document.body).getPropertyValue('--accent-primary-rgb').trim()}, 0.1)`;

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    for (let i = 0; i < diffBlocks.length; i++) {
        const x = (i % width) * blockWidth;
        const y = Math.floor(i / width) * blockHeight;
        
        ctx.fillStyle = diffBlocks[i] ? diffColor : sameColor;
        ctx.fillRect(x, y, blockWidth, blockHeight);
    }
}

function renderHexDiffView(bytes1, bytes2) {
    const viewer = document.getElementById('hex-diff-output');
    if (!viewer) return;
    viewer.style.display = 'block';
    viewer.innerHTML = '<div class="interpretation" style="margin-top:0; margin-bottom: 1rem;">Hex view of first 256 bytes. <span class="danger">Red text</span> indicates differing bytes.</div>';

    const len = Math.min(256, Math.max(bytes1.length, bytes2.length));
    let html = '';

    for (let i = 0; i < len; i += 16) {
        const offset = i.toString(16).padStart(8, '0');
        let row1 = `<div class="row"><span class="hex-offset">${offset}</span>`;
        let row2 = `<div class="row" style="margin-bottom: 0.5rem;"><span class="hex-offset"></span>`;
        let ascii1 = ' <span class="hex-ascii">';
        let ascii2 = ' <span class="hex-ascii">';

        for (let j = 0; j < 16; j++) {
            const currentOffset = i + j;
            if (currentOffset >= len) break;

            const byte1 = bytes1[currentOffset];
            const byte2 = bytes2[currentOffset];
            const diff = byte1 !== byte2;
            const diffClass = diff ? ' class="diff"' : '';

            row1 += `<span${diffClass}>${byte1 !== undefined ? byte1.toString(16).padStart(2, '0') : '  '}</span> `;
            row2 += `<span${diffClass}>${byte2 !== undefined ? byte2.toString(16).padStart(2, '0') : '  '}</span> `;
            ascii1 += byte1 !== undefined ? (byte1 >= 32 && byte1 <= 126 ? sanitizeHTML(String.fromCharCode(byte1)) : '.') : ' ';
            ascii2 += byte2 !== undefined ? (byte2 >= 32 && byte2 <= 126 ? sanitizeHTML(String.fromCharCode(byte2)) : '.') : ' ';
        }
        row1 += `${ascii1}</span></div>`;
        row2 += `${ascii2}</span></div>`;
        html += row1 + row2;
    }
    viewer.innerHTML += html;
}

async function analyzeMetadata() {
    const fileInput = document.getElementById('photo-upload');
    const output = document.getElementById('metadata-output');
    const aiBtn = document.getElementById('meta-ai-btn');
    aiBtn.style.display = 'none'; 

    if (!fileInput.files[0]) {
        output.innerHTML = '<span class="danger">Please select a file.</span>';
        return;
    }
    const file = fileInput.files[0];
    addCoCEntry('Metadata Analysis', file.name, 'low', 'Initiated metadata extraction.', 'auto');

    try {
        const tags = await ExifReader.load(file, { expanded: true });

        if (Object.keys(tags).length === 0 || (Object.keys(tags).length === 1 && tags.file)) {
            output.innerHTML = `<span class="warning">No significant EXIF/metadata found for ${sanitizeHTML(file.name)}.</span>`;
            addCoCEntry('Metadata Analysis', file.name, 'medium', `No metadata tags found.`, 'auto');
            return;
        }

        let allEntries = [];
        let keyFindings = {};
        let groupedTags = {}; // To build the full report

        // Single pass to process all tags
        for (const groupName in tags) {
            if (!tags[groupName] || typeof tags[groupName] !== 'object' || groupName === 'thumbnail') continue;
            
            groupedTags[groupName] = {};

            for (const tagName in tags[groupName]) {
                const tag = tags[groupName][tagName];
                if (tag && typeof tag.description !== 'undefined') {
                    const value = tag.description;
                    allEntries.push({ group: groupName, key: tagName, value });
                    groupedTags[groupName][tagName] = value;

                    // Populate key findings
                    const lowerKey = tagName.toLowerCase();
                    if (lowerKey.includes('datetimeoriginal')) keyFindings['Timestamp'] = value;
                    if (lowerKey.includes('software')) keyFindings['Software'] = value;
                    if (lowerKey.includes('make') || lowerKey.includes('model')) keyFindings['Device'] = `${keyFindings['Device'] || ''} ${value}`.trim();
                    if (lowerKey.includes('serialnumber')) keyFindings['Device Serial'] = value;
                    if (lowerKey.includes('author') || lowerKey.includes('creator')) keyFindings['Author'] = value;
                }
            }
        }

        const mapContainer = document.getElementById('map-container');
        // Defensive check for valid, numeric GPS coordinates before attempting to render the map.
        if (tags.gps && tags.gps.Latitude && typeof tags.gps.Latitude.description === 'number' && tags.gps.Longitude && typeof tags.gps.Longitude.description === 'number') {
            mapContainer.style.display = 'block';
            const lat = tags.gps.Latitude.description;
            const lon = tags.gps.Longitude.description;
            keyFindings['GPS'] = `${lat}, ${lon}`;
            renderMap(lat, lon);
        } else {
            mapContainer.style.display = 'none';
            if (mapInstance) { mapInstance.remove(); mapInstance = null; }
        }

        let keyFindingsHTML = '<div class="key-findings-box"><h3>Key Forensic Findings</h3>';
        if (Object.keys(keyFindings).length > 0) {
            for(const key in keyFindings) {
                const safeValue = sanitizeHTML(String(keyFindings[key]));
                keyFindingsHTML += `<div class="key-finding-item"><span class="key">${key}</span><span class="value">${safeValue}</span></div>`;
            }
        } else {
             keyFindingsHTML += `<div class="key-finding-item"><span class="key">No common forensic artifacts identified.</span></div>`;
        }
        keyFindingsHTML += '</div>';

        let fullReportHTML = '<details><summary>View Full Metadata Report</summary><div style="padding-left: 1rem; margin-top: 0.5rem;">';
        for (const groupName in groupedTags) {
            const groupHeader = `--- ${groupName.charAt(0).toUpperCase() + groupName.slice(1)} ---`;
            let groupContent = '';
            for (const tagName in groupedTags[groupName]) {
                const value = groupedTags[groupName][tagName];
                if (tagName.toLowerCase() === 'padding' || (typeof value === 'string' && value.length > 200)) {
                    groupContent += `${tagName.padEnd(30)}: [Large data block hidden]\n`;
                } else {
                    groupContent += `${tagName.padEnd(30)}: ${sanitizeHTML(String(value))}\n`;
                }
            }
            if (groupContent) {
                fullReportHTML += `<details><summary>${groupHeader}</summary><pre style="margin-top: 0.5rem; white-space: pre-wrap;">${groupContent}</pre></details>`;
            }
        }
        fullReportHTML += '</div></details>';
        
        output.innerHTML = keyFindingsHTML + fullReportHTML;
        analysisResults.metadata = { fileName: file.name, data: allEntries, totalTags: allEntries.length, keyFindings };
        addCoCEntry('Metadata Extracted', file.name, 'low', `Extracted ${allEntries.length} total tags.`, 'auto');
        aiBtn.style.display = 'flex';

    } catch (error) {
        console.error("Metadata analysis error:", error);
        output.innerHTML = `<span class="danger">Error analyzing metadata: ${sanitizeHTML(error.message)}.</span>`;
        addCoCEntry('Metadata Error', file.name, 'medium', `Error: ${error.message}`, 'auto');
    }
}

function renderMap(lat, lon) {
    const container = document.getElementById('map-container');
    if (mapInstance) {
        mapInstance.remove();
        mapInstance = null;
    }
    mapInstance = L.map(container).setView([lat, lon], 13);
    
    // Initial theme setup for the map
    updateMapTheme();

    L.marker([lat, lon]).addTo(mapInstance).bindPopup('Location from metadata.').openPopup();
}

// --- NEW: Map Theme Toggling ---
function updateMapTheme() {
    if (!mapInstance) return;

    // Remove the old tile layer if it exists
    if (mapInstance.tileLayer) {
        mapInstance.removeLayer(mapInstance.tileLayer);
    }

    const isLightTheme = document.body.classList.contains('light-theme');
    const tileUrl = isLightTheme 
        ? 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png' 
        : 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png';
    const attribution = isLightTheme
        ? '&copy; OpenStreetMap contributors'
        : '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>';

    const newTileLayer = L.tileLayer(tileUrl, {
        maxZoom: 19,
        attribution: attribution
    }).addTo(mapInstance);

    // Store a reference to the current tile layer so it can be removed later
    mapInstance.tileLayer = newTileLayer;
}

async function getMetadataAIInsights() {
    if (!analysisResults.metadata || !analysisResults.metadata.keyFindings) {
        alert("Please analyze a file first.");
        return;
    }

    const aiBtn = document.getElementById('meta-ai-btn');
    aiBtn.disabled = true;
    aiBtn.innerHTML = `<div class="loading-spinner" style="width: 1em; height: 1em; border-width: 2px;"></div>`;

    const prompt = `As a digital forensics expert, provide a concise narrative about the potential history and significance of a file based on these key metadata findings. What can you infer? What are the next logical steps for an investigator? Be direct and clear. \n\nKey Findings:\n${JSON.stringify(analysisResults.metadata.keyFindings, null, 2)}`;
    
    const aiResponse = await callGemini(prompt);
    const output = document.getElementById('metadata-output');
    const interpretationDiv = document.createElement('div');
    interpretationDiv.className = 'interpretation';
    interpretationDiv.innerHTML = `<strong>✨ AI Insights:</strong><br>${sanitizeHTML(aiResponse).replace(/\n/g, '<br>')}`;
    output.appendChild(interpretationDiv);

    aiBtn.disabled = false;
    aiBtn.innerHTML = `✨ Get AI Insights`;
}

async function analyzeSteganography() {
    const fileInput = document.getElementById('steg-file');
    const output = document.getElementById('steg-output');
    const previewCanvas = document.getElementById('steg-preview-canvas');
    
    if (!fileInput.files[0]) {
        output.innerHTML = '<span class="danger">Please select an image.</span>';
        return;
    }
    const file = fileInput.files[0];
    const channel = parseInt(document.getElementById('steg-channel').value);
    const bitPlane = parseInt(document.getElementById('steg-bit-plane').value);

    addCoCEntry('Stego Analysis', file.name, 'medium', `Initiated bit plane ${bitPlane} analysis on channel ${['R','G','B','A'][channel]}.`, 'auto');

    const reader = new FileReader();
    reader.onload = function(event) {
        const img = new Image();
        img.onload = function() {
            const canvas = document.createElement('canvas');
            canvas.width = img.width;
            canvas.height = img.height;
            const ctx = canvas.getContext('2d', { willReadFrequently: true });
            ctx.drawImage(img, 0, 0);
            
            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const data = imageData.data;
            const bitPlaneData = new Uint8ClampedArray(data.length);
            let extractedBits = [];
            const bitMask = 1 << bitPlane;

            for (let i = 0; i < data.length; i += 4) {
                const bit = (data[i + channel] & bitMask) > 0 ? 255 : 0;
                extractedBits.push(bit === 255 ? 1 : 0);
                bitPlaneData[i] = bit; bitPlaneData[i + 1] = bit; bitPlaneData[i + 2] = bit; bitPlaneData[i + 3] = 255;
            }
            
            previewCanvas.width = img.width;
            previewCanvas.height = img.height;
            const previewCtx = previewCanvas.getContext('2d');
            previewCtx.putImageData(new ImageData(bitPlaneData, img.width, img.height), 0, 0);
            previewCanvas.style.display = 'block';

            const entropy = calculateEntropy(new Uint8Array(extractedBits));
            const isSuspicious = entropy > 0.9;

            let resultText = `--- Bit Plane Analysis Report: ${sanitizeHTML(file.name)} ---\n\n`;
            resultText += `Image Dimensions: ${img.width}x${img.height}\n`;
            resultText += `Analyzed Channel: ${['Red', 'Green', 'Blue', 'Alpha'][channel]}\n`;
            resultText += `Analyzed Bit Plane: ${bitPlane} (${bitPlane === 0 ? 'LSB' : bitPlane === 7 ? 'MSB' : ''})\n`;
            resultText += `Bit Plane Entropy: ${entropy.toFixed(4)} / 1.0\n\n`;
            
            if (isSuspicious) {
                resultText += `<span class="danger">HIGH ENTROPY DETECTED</span>\n`;
                resultText += `<div class="interpretation"><strong>Interpretation:</strong> The entropy of this bit plane is abnormally high, suggesting it does not contain uniform image data. This is a strong indicator of embedded data. Visually inspect the bit plane image above for non-random patterns.</div>`;
            } else {
                resultText += `<span class="success">No evidence of high-entropy data found.</span>\n`;
                resultText += `<div class="interpretation"><strong>Interpretation:</strong> The entropy is low, which is consistent with natural image data. Hidden data may still exist, but it is not random-looking.</div>`;
            }
            
            output.innerHTML = resultText;
            analysisResults.steganography = { fileName: file.name, method: `Bit Plane ${bitPlane} (${['R','G','B','A'][channel]})`, riskLevel: isSuspicious ? 'High' : 'Low', entropy: entropy.toFixed(4), found: isSuspicious };
            addCoCEntry('Stego Scan Complete', file.name, isSuspicious ? 'high' : 'low', `${isSuspicious ? 'Suspicious data detected' : 'No obvious payload'}.`, 'auto');
        }
        img.onerror = () => { output.innerHTML = `<span class="danger">Could not load the selected file as an image.</span>`; }
        img.src = event.target.result;
    };
    reader.readAsDataURL(file);
}

function updatePasswordStrengthBarVisuals() {
    const password = document.getElementById('password-input').value;
    const scoreData = calculatePasswordScore(password);
    renderPasswordStrengthBar(scoreData);
}

async function analyzePassword() {
    const password = document.getElementById('password-input').value;
    const output = document.getElementById('password-output');
    
    if (!password) {
        output.innerHTML = '<span class="danger">Please enter a password.</span>';
        const scoreData = calculatePasswordScore('');
        renderPasswordStrengthBar(scoreData);
        return;
    }
    
    addCoCEntry('Password Analysis', '********', 'medium', 'Initiated strength analysis.', 'auto');
    
    const scoreData = calculatePasswordScore(password);
    const entropy = scoreData.entropy;
    const timeToCrack = formatTime((Math.pow(2, entropy) / 1e11) * 0.5); // 100 Giga-hashes/sec
    
    renderPasswordStrengthBar(scoreData);

    let resultHTML = `
        <div class="password-audit-grid">
            <div class="audit-metric">
                <span class="label">Password Entropy</span>
                <span class="value info">${entropy.toFixed(2)} bits</span>
            </div>
            <div class="audit-metric">
                <span class="label">Est. Crack Time</span>
                <span class="value ${entropy < 60 ? 'danger' : 'success'}">${timeToCrack}</span>
            </div>
        </div>
    `;
    
    if (scoreData.suggestions.length > 0) {
        resultHTML += `<div class="password-recommendations"><h4>Recommendations</h4><ul>`;
        scoreData.suggestions.forEach(sug => resultHTML += `<li>${sug}</li>`);
        resultHTML += `</ul></div>`;
    } else {
        resultHTML += `<div class="password-recommendations"><h4>Recommendations</h4><ul><li class="good-practice">This is a strong password. No immediate recommendations.</li></ul></div>`;
    }
    output.innerHTML = resultHTML;
    
    analysisResults.password = { timeToCrack, strength: scoreData.strengthText, entropyBits: entropy.toFixed(2), suggestions: scoreData.suggestions };
    addCoCEntry('Password Scan Complete', '********', entropy > 80 ? 'low' : (entropy > 60 ? 'medium' : 'high'), `Entropy: ${entropy.toFixed(2)} bits.`, 'auto');
}

function calculatePasswordScore(password) {
    let suggestions = [];
    const len = password.length;

    const checks = {
        length: len >= 12,
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        number: /\d/.test(password),
        symbol: /[^a-zA-Z\d]/.test(password)
    };

    let pool = 0;
    if (checks.lowercase) pool += 26;
    if (checks.uppercase) pool += 26;
    if (checks.number) pool += 10;
    if (checks.symbol) pool += 32;
    
    if (!checks.length) suggestions.push(`Increase length to at least 12 characters (currently ${len}).`);
    if (!checks.uppercase) suggestions.push("Add uppercase letters.");
    if (!checks.lowercase) suggestions.push("Add lowercase letters.");
    if (!checks.number) suggestions.push("Add numbers.");
    if (!checks.symbol) suggestions.push("Add symbols (e.g., !@#$).");

    const entropy = len * Math.log2(pool || 1);

    let score = 0;
    let strengthText = "Very Weak";
    if (entropy >= 100) { score = 100; strengthText = "Very Strong"; }
    else if (entropy >= 80) { score = 80; strengthText = "Strong"; }
    else if (entropy >= 60) { score = 60; strengthText = "Moderate"; }
    else if (entropy >= 40) { score = 40; strengthText = "Weak"; }
    else if (entropy > 0) { score = 20; strengthText = "Very Weak"; }
    
    return { score, suggestions, entropy, strengthText, checks };
}

function renderPasswordStrengthBar(scoreData) {
    const bar = document.getElementById('strength-bar-main');
    const text = document.getElementById('strength-text');
    
    let color = 'var(--danger)';
    if (scoreData.score >= 80) color = 'var(--success)';
    else if (scoreData.score >= 60) color = 'var(--warning)';

    bar.style.width = `${scoreData.score}%`;
    bar.style.backgroundColor = color;
    text.textContent = scoreData.strengthText;
    text.style.color = color;
}

function formatTime(seconds) {
    if (seconds < 1e-6) return "instantly";
    if (seconds < 60) return `${seconds.toPrecision(2)} seconds`;
    if (seconds < 3600) return `${(seconds / 60).toPrecision(2)} minutes`;
    if (seconds < 86400) return `${(seconds / 3600).toPrecision(2)} hours`;
    if (seconds < 31536000) return `${(seconds / 86400).toPrecision(2)} days`;
    const years = seconds / 31536000;
    if (years > 1e12) return "trillions of years";
    if (years > 1e9) return `${(years / 1e9).toPrecision(3)} billion years`;
    if (years > 1e6) return `${(years / 1e6).toPrecision(3)} million years`;
    if (years > 1000) return `${(years / 1000).toPrecision(3)} thousand years`;
    return `${years.toPrecision(3)} years`;
}

// --- ADVANCED NETWORK LOG ANALYZER ---
async function analyzeNetworkAdvanced() {
    const input = document.getElementById('network-input').value;
    const watchlistInput = document.getElementById('ip-watchlist').value;
    const output = document.getElementById('network-output');
    const aiBtn = document.getElementById('net-ai-btn');
    aiBtn.style.display = 'none';

    if (!input) {
        output.innerHTML = '<span class="danger">Please paste log data.</span>'; return;
    }
    addCoCEntry('Advanced Log Analysis', 'Pasted Data', 'medium', 'Initiated contextual threat analysis.', 'auto');

    // Parse the IP watchlist into a Set for efficient lookups
    const watchlistIPs = new Set(watchlistInput
        .split(/[\s,;\n]+/)
        .map(ip => ip.trim())
        .filter(ip => ip.length > 0)
    );

    const lines = input.split('\n').filter(line => line.trim() !== '');
    
    const sqlInjectionPattern = new RegExp('(union|select|insert|update|delete|drop|--|#|/\\*)', 'i');
    const ipRegex = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/; // Generic IP regex for watchlist check

    const patterns = {
        'Failed Login': { pattern: /failed password for(?: invalid user)? (\S+)/i, score: 1, type: 'auth_fail', extracts: { user: 1, ip: /from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/ } },
        'Successful Login': { pattern: /accepted password for (\S+)/i, score: 0, type: 'auth_success', extracts: { user: 1, ip: /from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/ } },
        'SSH Login': { pattern: /accepted publickey for (\S+)/i, score: 0, type: 'auth_success', extracts: { user: 1, ip: /from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/ } },
        'Sudo Command': { pattern: /sudo: \s*(\S+)\s*: TTY=.* PWD=.* USER=root COMMAND=(.*)/i, score: 3, type: 'priv_esc', extracts: { user: 1, command: 2 } },
        'SQL Injection Attempt': { pattern: sqlInjectionPattern, score: 10, type: 'web_attack' },
        'Directory Traversal': { pattern: /(\.\.\/|\.\.\\|etc\/passwd)/i, score: 10, type: 'web_attack' },
        'Suspicious User Agent': { pattern: /" (curl|wget|python|nmap|sqlmap|masscan)/i, score: 4, type: 'recon' },
        'Web Error': { pattern: /" (404|403|500) \d+/i, score: 1, type: 'web_error' }
    };

    let events = [];
    lines.forEach((line, index) => {
        for (const [name, p] of Object.entries(patterns)) {
            const match = line.match(p.pattern);
            if (match) {
                let details = { name, line: index + 1, score: p.score, type: p.type, content: line };
                if (p.extracts) {
                    for (const [key, extractor] of Object.entries(p.extracts)) {
                        if (typeof extractor === 'number') {
                            details[key] = match[extractor];
                        } else {
                            const detailMatch = line.match(extractor);
                            if (detailMatch) details[key] = detailMatch[1];
                        }
                    }
                }
                events.push(details);
                break; // Only match first pattern per line
            }
        }
    });

    let threats = [];
    const loginFails = events.filter(e => e.type === 'auth_fail');
    const failsByIp = loginFails.reduce((acc, e) => {
        if (e.ip) {
            acc[e.ip] = (acc[e.ip] || 0) + 1;
        }
        return acc;
    }, {});

    for (const [ip, count] of Object.entries(failsByIp)) {
        if (count >= 5) {
            const successAfter = events.find(e => e.type === 'auth_success' && e.ip === ip && e.line > loginFails.find(f => f.ip === ip).line);
            const risk = successAfter ? 'CRITICAL' : 'High';
            const score = successAfter ? 25 : 15;
            threats.push({
                name: `Brute-Force Attack${successAfter ? ' (Successful)' : ''}`,
                risk, score,
                details: `Detected ${count} failed login attempts from IP ${ip}, ${successAfter ? 'followed by a successful login.' : 'potentially ongoing.'}`
            });
        }
    }
    
    const successLogins = events.filter(e => e.type === 'auth_success');
    for (const login of successLogins) {
        const subsequentCommands = events.filter(e => e.type === 'priv_esc' && e.user === login.user && e.line > login.line);
        if (subsequentCommands.length > 0) {
            threats.push({
                name: 'Suspicious Post-Login Activity',
                risk: 'High', score: 20,
                details: `User '${login.user}' logged in from ${login.ip || 'unknown IP'} and then executed ${subsequentCommands.length} privileged command(s), starting with: ${subsequentCommands[0].command}`
            });
        }
    }

    events.filter(e => e.score >= 10).forEach(e => {
        threats.push({ name: e.name, risk: 'High', score: e.score, details: `Detected on line ${e.line}: ${e.content.substring(0, 100)}...` });
    });

    // Add threats for any IPs found on the watchlist
    if (watchlistIPs.size > 0) {
        const processedLines = new Set(); // Avoid duplicate alerts for the same line
        lines.forEach((line, index) => {
            const ipMatch = line.match(ipRegex);
            if (ipMatch && watchlistIPs.has(ipMatch[0]) && !processedLines.has(index)) {
                const matchedIp = ipMatch[0];
                threats.push({
                    name: 'IP Watchlist Hit',
                    risk: 'CRITICAL',
                    score: 25,
                    details: `IP address ${matchedIp} from the watchlist was detected on line ${index + 1}: ${line.substring(0, 100)}...`
                });
                addCoCEntry('IP Watchlist Hit', matchedIp, 'high', `IP found on line ${index + 1}.`, 'auto');
                processedLines.add(index);
            }
        });
    }

    // Sort threats by risk level to show most critical first
    const riskOrder = { 'CRITICAL': 0, 'High': 1, 'Medium': 2, 'Low': 3 };
    threats.sort((a, b) => (riskOrder[a.risk] || 99) - (riskOrder[b.risk] || 99));

    const totalScore = threats.reduce((sum, t) => sum + t.score, 0);
    let threatLevel, threatColor;
    if (totalScore >= 25) { threatLevel = 'CRITICAL'; threatColor = 'danger'; }
    else if (totalScore >= 15) { threatLevel = 'HIGH'; threatColor = 'danger'; }
    else if (totalScore >= 5) { threatLevel = 'MEDIUM'; threatColor = 'warning'; }
    else if (totalScore > 0) { threatLevel = 'LOW'; threatColor = 'info'; }
    else { threatLevel = 'Minimal'; threatColor = 'success'; }

    let resultHTML = `
        <div class="network-summary">
            <div>
                <span>Overall Threat Score</span>
                <span class="${threatColor}" style="font-size: 1.2em; font-weight: bold;">${totalScore}</span>
            </div>
            <div>
                <span>Assessed Threat Level</span>
                <span class="${threatColor}" style="font-size: 1.2em; font-weight: bold;">${threatLevel}</span>
            </div>
        </div>
    `;

    if (threats.length > 0) {
        resultHTML += `<h4>Correlated Threats Detected</h4>
            <table class="threat-table">
                <thead><tr><th>Risk</th><th>Threat</th><th>Details</th></tr></thead>
                <tbody>`;
        threats.forEach(t => {
            const riskColor = t.risk === 'CRITICAL' || t.risk === 'High' ? 'danger' : 'warning';
            resultHTML += `
                <tr>
                    <td><span class="${riskColor}">[${t.risk}]</span></td>
                    <td><strong>${t.name}</strong><br><small>(Score: ${t.score})</small></td>
                    <td class="threat-details-cell">${sanitizeHTML(t.details)}</td>
                </tr>
            `;
        });
        resultHTML += '</tbody></table>';
        aiBtn.style.display = 'flex';
    } else {
        resultHTML += `<p class="success" style="margin-top: 1rem;">No significant correlated threats detected.</p>`;
    }

    output.innerHTML = resultHTML;
    const riskDistribution = threats.reduce((acc, t) => {
        const risk = t.risk.toUpperCase();
        acc[risk] = (acc[risk] || 0) + 1;
        return acc;
    }, {});

    analysisResults.network = { risk: threatLevel, threats, score: totalScore, lines: lines.length, riskDistribution, allEvents: events };
    addCoCEntry('Advanced Log Scan Complete', `${lines.length} lines`, threatLevel.toLowerCase(), `Threat score: ${totalScore}. Found ${threats.length} correlated threats.`, 'auto');
}


async function getNetworkAIInsights() {
    if (!analysisResults.network || !analysisResults.network.threats || analysisResults.network.threats.length === 0) {
        alert("Please run an advanced analysis that detects threats first.");
        return;
    }

    const aiBtn = document.getElementById('net-ai-btn');
    aiBtn.disabled = true;
    aiBtn.innerHTML = `<div class="loading-spinner" style="width: 1em; height: 1em; border-width: 2px;"></div>`;

    const threatsForPrompt = analysisResults.network.threats.map(t => `- ${t.name} (Risk: ${t.risk}): ${t.details}`).join('\n');
    const prompt = `As a senior cybersecurity analyst, my advanced log analysis engine detected the following correlated threats. Please provide a concise, expert explanation of what these findings mean collectively. What is the likely attack scenario? What are the immediate, actionable recommendations for a forensic investigator? Be direct and clear.\n\nDetected Threats:\n${threatsForPrompt}`;
    
    const aiResponse = await callGemini(prompt);

    const output = document.getElementById('network-output');
    const interpretationDiv = document.createElement('div');
    interpretationDiv.className = 'interpretation';
    interpretationDiv.innerHTML = `<strong>✨ AI Explanation:</strong><br>${sanitizeHTML(aiResponse).replace(/\n/g, '<br>')}`;
    output.appendChild(interpretationDiv);

    aiBtn.disabled = false;
    aiBtn.innerHTML = `✨ Explain Threats with AI`;
}


// --- PROFESSIONAL PDF REPORTING ENGINE (ENHANCED v7.4) ---
async function exportToPDF() {
    // --- NEW: Validation for required fields ---
    const caseNameInput = document.getElementById('case-name');
    const investigatorNameInput = document.getElementById('investigator-name');
    
    let requiredFields = [caseNameInput, investigatorNameInput];
    let missingFields = false;

    requiredFields.forEach(input => {
        if (!input.value.trim()) {
            input.style.borderColor = 'var(--danger)';
            missingFields = true;
        } else {
            input.style.borderColor = ''; // Reset if filled
        }
    });

    if (missingFields) {
        alert('Please fill in all required fields (Case Name, Investigator Name) before generating a report.');
        return;
    }
    try {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF({ orientation: 'p', unit: 'mm', format: 'a4' });

        const caseInfo = {
            caseName: document.getElementById('case-name').value || "Unnamed Case",
            investigatorName: document.getElementById('investigator-name').value || "N/A",
            orgName: document.getElementById('org-name').value || "N/A",
            caseType: document.getElementById('case-type').value || "N/A",
            isCourtMode: document.getElementById('court-mode').checked,                    version: "P.H.A.N.I.X v8.0",
            sessionId: analysisResults.sessionId
        };

        // NEW: PDFReportBuilder class encapsulates all PDF creation logic.
        class PDFReportBuilder {
            constructor(doc, caseInfo) {
                this.doc = doc;
                this.caseInfo = caseInfo;
                this.yPos = 0;
                this.margin = 20;
                this.pageWidth = doc.internal.pageSize.getWidth();
                this.pageHeight = doc.internal.pageSize.getHeight();
                this.sectionCounter = { main: 1, sub: 1 };
                this.toc = [];
            }

            // --- Core PDF Building Blocks ---
            addPage() {
                this.doc.addPage();
                this.yPos = this.margin;
                this.addHeaders();
            }
            
            addHeaders() {
                const pageNum = this.doc.internal.getNumberOfPages();
                this.doc.setPage(pageNum);
                this.doc.setFont('helvetica', 'normal').setFontSize(9).setTextColor(80, 80, 80);
                this.doc.text(`Digital Forensic Report | Case: ${this.caseInfo.caseName}`, this.margin, 12);
                this.doc.text(`Page ${pageNum}`, this.pageWidth - this.margin, 12, { align: 'right' });
                this.doc.setDrawColor(220).line(this.margin, 15, this.pageWidth - this.margin, 15);
                this.doc.setFont('helvetica', 'normal').setFontSize(8).setTextColor(80, 80, 80);
                this.doc.text(`Report by ${this.caseInfo.investigatorName}`, this.margin, this.pageHeight - 10);
                this.doc.text(`Generated by ${this.caseInfo.version}`, this.pageWidth - this.margin, this.pageHeight - 10, { align: 'right' });
            }
            
            addWatermark() {
                const pageCount = this.doc.internal.getNumberOfPages();
                for (let i = 1; i <= pageCount; i++) {
                    this.doc.setPage(i);
                    this.doc.saveGraphicsState();
                    this.doc.setGState(new this.doc.GState({opacity: 0.08}));
                    this.doc.setFont('helvetica', 'bold');
                    this.doc.setFontSize(this.caseInfo.isCourtMode ? 80 : 100);
                    this.doc.setTextColor(0, 0, 0);                            const watermarkText = this.caseInfo.isCourtMode ? "FOR COURT USE ONLY" : "P.H.A.N.I.X";
                    this.doc.text(watermarkText, this.pageWidth / 2, this.pageHeight / 1.8, { angle: -45, align: 'center' });
                    this.doc.restoreGraphicsState();
                }
            }

            checkPageBreak(elementHeight) {
                if (this.yPos + elementHeight > this.pageHeight - (this.margin + 5)) {
                    this.addPage();
                }
            }

            addTitle(title, level = 1, toc = true) {
                const fontSize = level === 1 ? 18 : (level === 2 ? 14 : 11);
                const elementHeight = (fontSize * 0.7) + (level === 1 ? 8 : (level === 2 ? 6 : 4));
                let fullTitle = title;
                if (level === 1) {
                    fullTitle = `${this.sectionCounter.main}.0 ${title}`;
                    this.sectionCounter.main++;
                    this.sectionCounter.sub = 1;
                } else if (level === 2) {
                    fullTitle = `${this.sectionCounter.main - 1}.${this.sectionCounter.sub} ${title}`;
                    this.sectionCounter.sub++;
                }

                this.checkPageBreak(elementHeight);
                this.doc.setFont('helvetica', 'bold').setFontSize(fontSize).setTextColor(0, 102, 153); // Dark Electric Blue
                this.doc.text(fullTitle, this.margin, this.yPos);
                if(toc) this.toc.push({ title: fullTitle, page: this.doc.internal.getNumberOfPages(), y: this.yPos, level });
                this.yPos += elementHeight;
            }

            addSectionHeader(title) {
                const fullTitle = `${this.sectionCounter.main}.0 ${title}`;
                this.sectionCounter.main++;
                this.sectionCounter.sub = 1;
                this.checkPageBreak(20);
                this.doc.setFillColor(0, 102, 153); // Dark Electric Blue
                this.doc.rect(this.margin, this.yPos - 10, this.pageWidth - (this.margin * 2), 12, 'F');
                this.doc.setFont('helvetica', 'bold').setFontSize(16).setTextColor(255, 255, 255);
                this.doc.text(fullTitle, this.margin + 3, this.yPos);
                this.toc.push({ title: fullTitle, page: this.doc.internal.getNumberOfPages(), y: this.yPos, level: 1 });
                this.yPos += 10;
            }

            addText(text) {
                const splitText = this.doc.splitTextToSize(text, this.pageWidth - this.margin * 2);
                const textHeight = this.doc.getTextDimensions(splitText).h + 5;
                this.checkPageBreak(textHeight);
                this.doc.setFont('helvetica', 'normal').setFontSize(11).setTextColor(0,0,0);
                this.doc.text(splitText, this.margin, this.yPos, { lineHeightFactor: 1.5 });
                this.yPos += textHeight;
            }

            addTable(head, body, columnStyles = {}) {
                const tableHeight = (body.length + 1) * 10 + 10;
                this.checkPageBreak(tableHeight);
                this.doc.autoTable({
                    startY: this.yPos,
                    head: [head],
                    body: body,
                    theme: 'grid',
                    headStyles: { fillColor: [0, 102, 153] }, // Dark Electric Blue
                    styles: { cellPadding: 2, fontSize: 9 },
                    columnStyles: columnStyles
                });
                this.yPos = this.doc.autoTable.previous.finalY + 10;
            }
            
            // --- Report Section Builders ---

            addCoverPage() {
                this.yPos = 60;
                this.doc.setFont('helvetica', 'bold').setFontSize(26).setTextColor(0, 102, 153).text("Digital Forensic Examination Report", this.pageWidth / 2, this.yPos, { align: 'center' });
                this.yPos += 10;
                this.doc.setFont('helvetica', 'normal').setFontSize(14).setTextColor(80, 80, 80).text(this.caseInfo.version, this.pageWidth / 2, this.yPos, { align: 'center' });
                this.yPos += 25;
                this.doc.autoTable({
                    startY: this.yPos, theme: 'plain', styles: { font: 'helvetica', fontSize: 11, cellPadding: 5 },
                    body: [
                        [{content: 'Case ID / Name:', styles:{fontStyle:'bold', cellWidth: 50}}, this.caseInfo.caseName],
                        [{content: 'Case Type:', styles:{fontStyle:'bold', cellWidth: 50}}, this.caseInfo.caseType],
                        [{content: 'Organization:', styles:{fontStyle:'bold', cellWidth: 50}}, this.caseInfo.orgName],
                        [{content: 'Lead Investigator:', styles:{fontStyle:'bold', cellWidth: 50}}, this.caseInfo.investigatorName],
                        [{content: 'Report Date:', styles:{fontStyle:'bold', cellWidth: 50}}, new Date().toUTCString()],
                    ]
                });
            }

            addTableOfContents() {
                this.addPage();
                this.addSectionHeader("Table of Contents");

                this.toc.forEach(item => {
                    this.checkPageBreak(8);
                    this.doc.setFont('helvetica', 'normal').setFontSize(11);
                    const indent = (item.level - 1) * 8;
                    const titleWidth = this.doc.getTextWidth(item.title);
                    const pageNumWidth = this.doc.getTextWidth(item.page.toString());
                    const availableWidth = this.pageWidth - (this.margin * 2) - indent - titleWidth - pageNumWidth - 4;

                    // Draw link first
                    if (item.level === 1) {
                        this.doc.setFont('helvetica', 'bold').setTextColor(0, 102, 153);
                    } else {
                        this.doc.setFont('helvetica', 'normal').setTextColor(0, 170, 255);
                    }
                    this.doc.textWithLink(item.title, this.margin + indent, this.yPos, { pageNumber: item.page, y: item.y });

                    // Draw dot leaders
                    this.doc.setTextColor(150, 150, 150);
                    if (availableWidth > 0) {
                        const dots = '.'.repeat(Math.floor(availableWidth / this.doc.getTextWidth('.')));
                        this.doc.text(dots, this.margin + indent + titleWidth + 2, this.yPos, { align: 'left' });
                    }

                    // Draw page number
                    this.doc.setTextColor(0, 0, 0);
                    this.doc.text(`${item.page}`, this.pageWidth - this.margin, this.yPos, { align: 'right' });
                    this.yPos += 8;
                });
            }

            addExecutiveSummary() {
                this.addPage();
                this.addSectionHeader("Executive Summary");
                let summaryText = `This report details the forensic findings for Case: ${this.caseInfo.caseName}. The examination was conducted using the ${this.caseInfo.version} toolkit.\n\n`;
                
                const findings = Object.keys(analysisResults).filter(k => k !== 'sessionId');
                if (findings.length === 0) {
                    summaryText += "No analyses were performed in this session.";
                } else {
                    summaryText += "The following analyses were performed in this session:\n";
                    findings.forEach(finding => {
                        const findingName = finding.charAt(0).toUpperCase() + finding.slice(1).replace(/([A-Z])/g, ' $1').trim();
                        summaryText += `• ${findingName} Analysis\n`;
                    });
                }
                this.addText(summaryText);
            }
            
            addDetailedFindings() {
                this.addPage();
                this.addSectionHeader("Detailed Forensic Findings");
                if (Object.keys(analysisResults).length <= 1) {
                    this.addText("No analysis results to report.");
                    return;
                }
                if (analysisResults.fileHash) this.addFileIntegritySection();
                if (analysisResults.comparison) this.addComparisonSection();
                if (analysisResults.metadata) this.addMetadataSection();
                if (analysisResults.steganography) this.addStegoSection();
                if (analysisResults.password) this.addPasswordSection();
                if (analysisResults.network) this.addNetworkSection();
            }

            addFileIntegritySection() {
                this.addTitle("File Integrity & Threat Scan", 2);
                const res = analysisResults.fileHash;
                this.addTable(['Property', 'Value'], [
                    ['Filename', res.fileName],
                    ['File Size', `${res.fileSize.toLocaleString()} bytes`],
                    ['Identified Type', res.fileType],
                    ['MD5 Hash', res.hashes.md5],
                    ['SHA-1 Hash', res.hashes.sha1],
                    ['SHA-256 Hash', res.hashes.sha256],
                    ['Shannon Entropy (Overall)', res.entropy.toFixed(4)],
                    ['Entropy Assessment', res.entropyAssessment || 'N/A'],
                    ['Threat Status', res.isMalicious ? `THREAT: ${res.threatName}` : 'Clean']
                ], { 0: { cellWidth: 50 }, 1: { styles: { font: 'courier' } } });
                
                if (res.blockEntropy) {
                    this.addTable(['Block Entropy Metric', 'Value'], [
                        ['Minimum Block Entropy', res.blockEntropy.min.toFixed(4)],
                        ['Maximum Block Entropy', res.blockEntropy.max.toFixed(4)],
                        ['Average Block Entropy', res.blockEntropy.average.toFixed(4)],
                    ], { 0: { cellWidth: 50 } });
                }
                
                const freqChartCanvas = document.getElementById('entropy-chart');
                if (freqChartCanvas && freqChartCanvas.style.display !== 'none') {
                    try {
                        const chartImage = freqChartCanvas.toDataURL('image/png');
                        this.addTitle("Byte Frequency Chart", 3, false);
                        this.checkPageBreak(70);
                        this.doc.addImage(chartImage, 'PNG', (this.pageWidth - 120) / 2, this.yPos, 120, 60);
                        this.yPos += 70;
                        this.doc.setFont('helvetica', 'italic').setFontSize(9).setTextColor(80, 80, 80).text("Figure: Distribution of byte values from 0x00 to 0xFF.", this.pageWidth / 2, this.yPos, { align: 'center' });
                        this.yPos += 5;
                    } catch (e) { console.error("Could not add entropy chart to PDF", e); }
                }

                const plotChartCanvas = document.getElementById('byte-plot-chart');
                if (plotChartCanvas && plotChartCanvas.style.display !== 'none') {
                    try {
                        const chartImage = plotChartCanvas.toDataURL('image/png');
                        this.addTitle("File Entropy Plot", 3, false);
                        this.checkPageBreak(85);
                        this.doc.addImage(chartImage, 'PNG', (this.pageWidth - 160) / 2, this.yPos, 160, 70);
                        this.yPos += 80;
                        this.doc.setFont('helvetica', 'italic').setFontSize(9).setTextColor(80, 80, 80).text("Figure: Shannon entropy calculated over sequential blocks of the file.", this.pageWidth / 2, this.yPos, { align: 'center' });
                        this.yPos += 5;
                    } catch (e) { console.error("Could not add entropy plot chart to PDF", e); }
                }
            }

            addComparisonSection() {
                this.addTitle("File Comparison Analysis", 2);
                const res = analysisResults.comparison;
                if (!res) return;

                this.addTable(['Property', 'File 1: ' + res.file1.name, 'File 2: ' + res.file2.name], [
                    ['File Size', `${res.file1.size.toLocaleString()} bytes`, `${res.file2.size.toLocaleString()} bytes`],
                    ['MD5', res.file1.hashes.md5, res.file2.hashes.md5],
                    ['SHA-1', res.file1.hashes.sha1, res.file2.hashes.sha1],
                    ['SHA-256', res.file1.hashes.sha256, res.file2.hashes.sha256],
                ], { 1: { styles: { font: 'courier' } }, 2: { styles: { font: 'courier' } } });

                if (res.areIdentical) {
                    this.addText("Conclusion: The files are cryptographically identical.");
                } else {
                    this.addText("Conclusion: The files are different.");
                    
                    const diffMapCanvas = document.getElementById('diff-map-canvas');
                    if (diffMapCanvas && diffMapCanvas.style.display !== 'none') {
                        try {
                            const chartImage = diffMapCanvas.toDataURL('image/png');
                            this.addTitle("File Difference Map", 3, false);
                            this.checkPageBreak(40);
                            this.doc.addImage(chartImage, 'PNG', (this.pageWidth - 170) / 2, this.yPos, 170, 30);
                            this.yPos += 40;
                            this.doc.setFont('helvetica', 'italic').setFontSize(9).setTextColor(80, 80, 80).text("Figure: A visual map of the file differences. Red areas indicate changed blocks.", this.pageWidth / 2, this.yPos, { align: 'center' });
                            this.yPos += 10;
                        } catch (e) { console.error("Could not add diff map to PDF", e); }
                    }

                    this.addTitle("Hex Difference View (First 256 Bytes)", 3, false);
                    this.addHexDiffToPdf(res.firstBytes1, res.firstBytes2, 256);
                }
            }

            addHexDiffToPdf(bytes1, bytes2, limit) {
                const len = Math.min(limit, Math.max(bytes1.length, bytes2.length));
                this.doc.setFont('courier', 'normal').setFontSize(8);
                this.checkPageBreak(10);

                for (let i = 0; i < len; i += 16) {
                    this.checkPageBreak(8); // Check for each pair of rows
                    let ascii1 = '', ascii2 = '';
                    let coloredSegments1 = [], coloredSegments2 = [];

                    for (let j = 0; j < 16; j++) {
                        const offset = i + j;
                        const byte1 = offset < bytes1.length ? bytes1[offset] : null;
                        const byte2 = offset < bytes2.length ? bytes2[offset] : null;
                        const diff = byte1 !== byte2;

                        if (byte1 !== null) { coloredSegments1.push({ text: byte1.toString(16).padStart(2, '0') + ' ', color: diff ? 'red' : 'black' }); ascii1 += byte1 >= 32 && byte1 <= 126 ? String.fromCharCode(byte1) : '.'; } else { coloredSegments1.push({ text: '   ', color: 'black' }); ascii1 += ' '; }
                        if (byte2 !== null) { coloredSegments2.push({ text: byte2.toString(16).padStart(2, '0') + ' ', color: diff ? 'red' : 'black' }); ascii2 += byte2 >= 32 && byte2 <= 126 ? String.fromCharCode(byte2) : '.'; } else { coloredSegments2.push({ text: '   ', color: 'black' }); ascii2 += ' '; }
                    }

                    const offsetHex = i.toString(16).padStart(8, '0');
                    this.doc.setTextColor(80, 80, 80).text(offsetHex, this.margin, this.yPos);
                    
                    let xPos = this.margin + 25;
                    coloredSegments1.forEach(seg => { this.doc.setTextColor(seg.color === 'red' ? 239 : 0, seg.color === 'red' ? 68 : 0, seg.color === 'red' ? 68 : 0); this.doc.text(seg.text, xPos, this.yPos); xPos += this.doc.getTextWidth(seg.text); });
                    this.doc.setTextColor(0,0,0).text(ascii1, xPos + 5, this.yPos); this.yPos += 4;

                    xPos = this.margin + 25;
                    coloredSegments2.forEach(seg => { this.doc.setTextColor(seg.color === 'red' ? 239 : 0, seg.color === 'red' ? 68 : 0, seg.color === 'red' ? 68 : 0); this.doc.text(seg.text, xPos, this.yPos); xPos += this.doc.getTextWidth(seg.text); });
                    this.doc.setTextColor(0,0,0).text(ascii2, xPos + 5, this.yPos); this.yPos += 6;
                }
            }

            addMetadataSection() {
                this.addTitle("Metadata Analysis", 2);
                const res = analysisResults.metadata;
                if (Object.keys(res.keyFindings).length > 0) {
                    this.addTitle("Key Findings", 3, false);
                    const findingsBody = Object.entries(res.keyFindings);
                    if (document.getElementById('map-container').style.display !== 'none') { findingsBody.push(['Note', 'GPS coordinates were visualized on an interactive map within the tool.']); }
                    this.addTable(['Key Finding', 'Value'], findingsBody, { 0: { cellWidth: 40 } });
                }
                this.addTitle("All Extracted Metadata", 3, false);
                const allMetaBody = res.data.map(d => [d.group, d.key, d.value]);
                this.addTable(['Group', 'Tag', 'Value'], allMetaBody, { 0: { cellWidth: 30 }, 1: { cellWidth: 40 } });
            }
            
            addStegoSection() {
                this.addTitle("Steganography Analysis", 2);
                const res = analysisResults.steganography;
                this.addTable(['Property', 'Value'], [
                    ['Filename', res.fileName],
                    ['Analysis Method', res.method],
                    ['LSB Alpha Entropy', res.entropy],
                    ['Result', res.found ? 'High probability of hidden data' : 'No evidence found']
                ], { 0: { cellWidth: 50 } });

                const chartCanvas = document.getElementById('steg-preview-canvas');
                if (chartCanvas && chartCanvas.style.display !== 'none') {
                    try {
                        const chartImage = chartCanvas.toDataURL('image/png');
                        this.addTitle("Bit Plane Visualization", 3, false);
                        this.checkPageBreak(85);
                        this.doc.text("The following image represents the extracted bit plane (white=1, black=0):", this.margin, this.yPos);
                        this.yPos += 8;
                        this.doc.addImage(chartImage, 'PNG', (this.pageWidth - 90) / 2, this.yPos, 90, 70, undefined, 'FAST');
                        this.yPos += 80;
                        this.doc.setFont('helvetica', 'italic').setFontSize(9).setTextColor(80, 80, 80).text("Figure: Visual representation of the selected bit plane.", this.pageWidth / 2, this.yPos, { align: 'center' });
                        this.yPos += 5;
                    } catch (e) { console.error("Could not add stego chart to PDF", e); }
                }
            }
            
            addPasswordSection() {
                this.addTitle("Password Audit", 2);
                const res = analysisResults.password;
                this.addTable(['Metric', 'Result'], [
                    ['Strength', res.strength],
                    ['Entropy', `${res.entropyBits} bits`],
                    ['Estimated Crack Time', res.timeToCrack],
                    ['Recommendations', res.suggestions.join('\n')]
                ], { 0: { cellWidth: 50 } });
            }
            
            async addNetworkSection() {
                this.addTitle("Network Log Analysis", 2);
                const res = analysisResults.network;
                this.addTable(['Metric', 'Value'], [
                    ['Lines Analyzed', res.lines],
                    ['Overall Threat Score', res.score],
                    ['Assessed Threat Level', res.risk],
                    ['Correlated Threats Found', res.threats.length],
                ], { 0: { cellWidth: 50 } });
                
                if (res.threats.length > 0) {
                    this.addTitle("Correlated Threats", 3, false);
                    const threatsBody = res.threats.map(t => [t.risk, t.name, t.details]);
                    this.addTable(['Risk', 'Threat Name', 'Details'], threatsBody, { 0: { cellWidth: 25 }, 1: { cellWidth: 45 } });
                }

                if (res.allEvents && res.allEvents.length > 0) {
                    this.addTitle("All Detected Events Log", 3, false);
                    const eventsBody = res.allEvents.map(e => [e.line, e.name, e.type, e.score]);
                    this.addTable(['Line #', 'Event Name', 'Type', 'Score'], eventsBody, { 0: { cellWidth: 20 }, 3: { cellWidth: 20 } });
                }
            }

            addCaseNotesSection() {
                const notes = document.getElementById('case-notes-textarea').value;
                if (notes && notes.trim() !== '') {
                    this.addPage();
                    this.addTitle("Investigator's Case Notes");
                    this.addText(notes);
                }
            }

            addChainOfCustodySection() {
                this.addPage();
                this.addTitle("Chain of Custody Log");
                this.addText("Each entry is cryptographically linked to the previous one, ensuring the integrity of the log. Any modification to an entry will invalidate the entire chain that follows.");

                if (chainOfCustody.length === 0) {
                    this.addText("No chain of custody events were recorded for this session.");
                    return;
                }

                const cocBody = chainOfCustody.map(entry => [
                    entry.timestamp,
                    entry.action,
                    entry.target,
                    entry.hash.substring(0, 16) + '...'
                ]);

                this.addTable(['Timestamp', 'Action', 'Target', 'Entry Hash (SHA-256)'], cocBody, { 0: { cellWidth: 35 }, 3: { styles: { font: 'courier', fontSize: 7 }, cellWidth: 40 } });
                const finalHash = chainOfCustody[0].hash;
                this.addTitle("Final Chain Integrity Hash", 3, false);
                this.addText(`The hash of the final entry, which validates the entire chain, is:\n${finalHash}`);
            }

            addAttestationSection() {
                this.addPage();
                this.addTitle("Investigator's Attestation");
                const attestText = "I, the undersigned, attest that the information contained within this report is accurate to the best of my knowledge and that all procedures were conducted in a forensically sound manner.";
                this.addText(attestText);
                this.yPos += 30;
                this.doc.setDrawColor(100).line(this.margin, this.yPos, this.margin + 80, this.yPos);
                this.yPos += 5;
                this.doc.text(`Signature: ${this.caseInfo.investigatorName}`, this.margin, this.yPos);
            }
            
            async build() {
                // --- Build Document ---
                this.addCoverPage();
                
                // --- Build Content Pages ---
                this.addExecutiveSummary();
                this.addDetailedFindings();
                this.addCaseNotesSection();
                this.addChainOfCustodySection();
                this.addAttestationSection();
                
                // --- Finalize: Build TOC, Watermark, and Headers ---
                const totalPages = this.doc.internal.getNumberOfPages();
                this.addTableOfContents();
                this.addWatermark();

                // Re-add headers to all pages to ensure they are on top of the watermark
                for (let i = 1; i <= totalPages + 1; i++) {
                    this.doc.setPage(i);
                    this.addHeaders();
                }
            }
        }

        const builder = new PDFReportBuilder(doc, caseInfo);
        await builder.build();

        doc.setProperties({
            title: `Forensic Report: ${caseInfo.caseName}`,
            subject: `Digital evidence analysis for case ${caseInfo.caseName}`,
            author: caseInfo.investigatorName,
            keywords: `forensic, report, ${caseInfo.caseType}, ${caseInfo.sessionId}`,
            creator: caseInfo.version
        });

        addCoCEntry('Report Exported', `${caseInfo.caseName}.pdf`, 'low', `PDF report generated.`, 'auto');
        doc.save(`NITTALA-Report-${caseInfo.caseName}.pdf`);

        // --- NEW: Fix for browser title changing after PDF save ---
        // Provide immediate feedback in the tab title, then revert after a few seconds.
        const originalTitle = document.title;
        document.title = `✓ P.H.A.N.I.X Report Generated`;
        setTimeout(() => { document.title = originalTitle; }, 5000);

    
    } catch (e) {
        console.error("PDF Generation Error:", e);
        alert("Failed to generate PDF. Check console for details.");
    }
}

function addCoCEntry(action, target, status, details, type = 'auto') {
    // Get the hash of the last entry (which is the first element since we unshift)
    const previousHash = chainOfCustody.length > 0 ? chainOfCustody[0].hash : '0'.repeat(64);
    const now = new Date();

    const entryData = {
        id: now.getTime(),
        action, 
        target, 
        status, 
        type,
        details: `${details} (Session: ${analysisResults.sessionId})`, 
        timestamp: now.toLocaleString('en-US', { dateStyle: 'short', timeStyle: 'medium' }),
        previousHash: previousHash
    };

    // Create a consistent string representation of the entry to hash
    const entryString = `${entryData.id}|${entryData.action}|${entryData.target}|${entryData.status}|${entryData.type}|${entryData.details}|${entryData.timestamp}|${entryData.previousHash}`;
    const currentHash = CryptoJS.SHA256(entryString).toString();

    const finalEntry = { ...entryData, hash: currentHash };

    chainOfCustody.unshift(finalEntry);
    if (chainOfCustody.length > 100) chainOfCustody.pop();
    renderCoC();
}

function renderCoC() {
    const container = document.getElementById('coc-log');
    if (!container) return;
    container.innerHTML = '';
    if (chainOfCustody.length === 0) {
        container.innerHTML = '<p style="font-size: 0.9rem; color: var(--text-secondary); padding-left: 0;">Log is empty. Start an analysis to populate.</p>';
        return;
    }
    chainOfCustody.forEach(entry => {
        const el = document.createElement('div');
        el.className = 'coc-entry';
        el.onclick = () => showCoCDetails(entry.id);
        el.innerHTML = `
            <span class="coc-status status-${entry.status}"></span>
            <div class="coc-info">
                <span class="coc-action">${entry.action}</span>
                <span class="coc-meta">${entry.timestamp}</span>
                <span class="coc-target">Target: ${entry.target}</span>
            </div>`;
        container.appendChild(el);
    });
}

function showCoCDetails(id) {
    const entry = chainOfCustody.find(e => e.id === id);
    if (!entry) return;
    document.getElementById('modal-title').textContent = `${entry.action} Details`;
    const detailsText = `Action:    ${entry.action}\nTarget:    ${entry.target}\nStatus:    ${entry.status ? entry.status.toUpperCase() : 'N/A'}\nTimestamp: ${entry.timestamp}\n\nDetails:\n${entry.details}\n\n--- Cryptographic Integrity ---\nPrevious Entry Hash: ${entry.previousHash}\nCurrent Entry Hash:  ${entry.hash}`;
    document.getElementById('modal-body').textContent = detailsText;

    document.getElementById('coc-modal').classList.add('active');
}

function closeModal() { document.getElementById('coc-modal').classList.remove('active'); }
function closeTimelineModal() { document.getElementById('timeline-modal').classList.remove('active'); }
function closeAddCocModal() { document.getElementById('add-coc-modal').classList.remove('active'); }
function openAddCocModal() { document.getElementById('add-coc-modal').classList.add('active'); }

function getIconForAction(entry) {
    if (entry.type === 'manual') return 'fa-pencil-alt';

    const lowerAction = entry.action.toLowerCase();
    if (lowerAction.includes('scan') || lowerAction.includes('analysis') || lowerAction.includes('analyze')) return 'fa-search';
    if (lowerAction.includes('acquired') || lowerAction.includes('loaded')) return 'fa-upload';
    if (lowerAction.includes('exported') || lowerAction.includes('saved')) return 'fa-save';
    if (lowerAction.includes('started')) return 'fa-play-circle';
    if (lowerAction.includes('extracted') || lowerAction.includes('metadata')) return 'fa-tags';
    if (lowerAction.includes('comparison')) return 'fa-exchange-alt';
    if (lowerAction.includes('password')) return 'fa-key';
    if (lowerAction.includes('stego')) return 'fa-eye-slash';
    return 'fa-info-circle';
}

function renderTimeline() {
    const container = document.getElementById('timeline-body');
    if (!container || chainOfCustody.length === 0) {
        container.innerHTML = '<p>No events in the Chain of Custody log yet.</p>';
        return;
    }

    // The CoC is stored with newest first, so we reverse for a chronological timeline
    const chronologicalCoC = [...chainOfCustody].reverse(); 

    let timelineHTML = '<div class="timeline-container">';

    chronologicalCoC.forEach(entry => {
        const iconClass = getIconForAction(entry);
        timelineHTML += `
            <div class="timeline-item">
                <div class="timeline-dot status-${entry.status}">
                    <i class="fas ${iconClass}"></i>
                </div>
                <div class="timeline-content" onclick="showCoCDetails(${entry.id})">
                    <h4>${entry.action}</h4>
                    <div class="time">${entry.timestamp}</div>
                    <p><strong>Target:</strong> ${entry.target}</p>
                </div>
            </div>`;
    });

    timelineHTML += '</div>';
    container.innerHTML = timelineHTML;
}

function openTimelineModal() {
    renderTimeline();
    document.getElementById('timeline-modal').classList.add('active');
}

function submitManualCoCEntry() {
    const action = document.getElementById('coc-manual-action').value.trim();
    const target = document.getElementById('coc-manual-target').value.trim();
    const status = document.getElementById('coc-manual-status').value;
    const details = document.getElementById('coc-manual-details').value.trim();

    if (!action || !target) {
        alert("Please fill in at least the Action and Target fields.");
        return;
    }

    addCoCEntry(action, target, status, details || 'Manual entry.', 'manual');

    // Clear the form and close the modal
    document.getElementById('coc-manual-action').value = '';
    document.getElementById('coc-manual-target').value = '';
    document.getElementById('coc-manual-details').value = '';
    document.getElementById('coc-manual-status').value = 'medium';
    closeAddCocModal();
}

// --- NEW: Parallax grid and sound for new hero section ---
document.addEventListener('mousemove', (e) => {
    const grid = document.getElementById('grid');
    if (grid) {
        const moveX = (e.clientX / window.innerWidth - 0.5) * 20;
        const moveY = (e.clientY / window.innerHeight - 0.5) * 20;
        grid.style.transform = `translate(${moveX}px, ${moveY}px)`;
    }
});