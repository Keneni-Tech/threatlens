(() => {
    "use strict";

    document.addEventListener("click", (event) => {
        const dismissButton = event.target.closest(
            "[data-dismiss-message]"
        );

        if (!dismissButton) {
            return;
        }

        dismissButton.closest(".application-message")?.remove();
    });

    const investigationForm = document.querySelector(
        "[data-investigation-form]"
    );

    if (!investigationForm) {
        return;
    }

    const textarea = investigationForm.querySelector(
        'textarea[name="security_events"]'
    );
    const fileInput = investigationForm.querySelector(
        'input[type="file"][name="event_file"]'
    );
    const submitButton = document.getElementById(
        "analysis-submit-button"
    );
    const submitLabel = submitButton?.querySelector(
        "[data-submit-label]"
    );
    const loadingOverlay = document.getElementById(
        "analysis-loading-overlay"
    );
    const characterCount = document.getElementById(
        "character-count"
    );
    const selectedFileName = document.getElementById(
        "selected-file-name"
    );
    const sampleElement = document.getElementById(
        "sample-events-data"
    );
    const loadSampleButton = document.getElementById(
        "load-sample"
    );
    const pasteTab = document.getElementById("paste-tab");
    const uploadTab = document.getElementById("upload-tab");
    const pastePanel = document.getElementById("paste-panel");
    const uploadPanel = document.getElementById("upload-panel");

    const requiredElements = [
        textarea,
        fileInput,
        submitButton,
        submitLabel,
        loadingOverlay,
        characterCount,
        selectedFileName,
        sampleElement,
        loadSampleButton,
        pasteTab,
        uploadTab,
        pastePanel,
        uploadPanel,
    ];

    if (requiredElements.some((element) => !element)) {
        return;
    }

    const inputTabs = [pasteTab, uploadTab];
    const inputPanels = [pastePanel, uploadPanel];

    const activateInputMethod = (activeIndex) => {
        inputTabs.forEach((tab, index) => {
            const isActive = index === activeIndex;

            tab.classList.toggle("is-active", isActive);
            tab.setAttribute(
                "aria-selected",
                String(isActive)
            );
            tab.setAttribute(
                "tabindex",
                isActive ? "0" : "-1"
            );
            inputPanels[index].hidden = !isActive;
        });
    };

    const formatFileSize = (bytes) => {
        if (bytes < 1024) {
            return `${bytes} bytes`;
        }

        if (bytes < 1024 * 1024) {
            return `${(bytes / 1024).toFixed(1)} KB`;
        }

        return `${(
            bytes / (1024 * 1024)
        ).toFixed(1)} MB`;
    };

    const updateCharacterCount = () => {
        characterCount.textContent = (
            `${textarea.value.length.toLocaleString()} characters`
        );
    };

    const updateSelectedFile = () => {
        const file = fileInput.files[0];

        selectedFileName.textContent = file
            ? `${file.name} · ${formatFileSize(file.size)}`
            : "No file selected";
    };

    const resetSubmissionState = () => {
        submitButton.disabled = false;
        submitLabel.textContent = (
            "Analyze and save investigation"
        );
        loadingOverlay.hidden = true;
        investigationForm.removeAttribute("aria-busy");
        document.body.classList.remove(
            "analysis-in-progress"
        );
    };

    investigationForm.addEventListener("submit", (event) => {
        if (
            investigationForm.getAttribute("aria-busy")
            === "true"
        ) {
            event.preventDefault();
            return;
        }

        if (!investigationForm.checkValidity()) {
            return;
        }

        submitButton.disabled = true;
        submitLabel.textContent = "Analyzing events...";
        loadingOverlay.hidden = false;
        investigationForm.setAttribute("aria-busy", "true");
        document.body.classList.add(
            "analysis-in-progress"
        );
    });

    window.addEventListener("pageshow", resetSubmissionState);

    inputTabs.forEach((tab, index) => {
        tab.addEventListener(
            "click",
            () => activateInputMethod(index)
        );

        tab.addEventListener("keydown", (event) => {
            let targetIndex = null;

            if (
                event.key === "ArrowRight"
                || event.key === "ArrowDown"
            ) {
                targetIndex = (index + 1) % inputTabs.length;
            } else if (
                event.key === "ArrowLeft"
                || event.key === "ArrowUp"
            ) {
                targetIndex = (
                    index - 1 + inputTabs.length
                ) % inputTabs.length;
            } else if (event.key === "Home") {
                targetIndex = 0;
            } else if (event.key === "End") {
                targetIndex = inputTabs.length - 1;
            }

            if (targetIndex === null) {
                return;
            }

            event.preventDefault();
            activateInputMethod(targetIndex);
            inputTabs[targetIndex].focus();
        });
    });

    loadSampleButton.addEventListener("click", () => {
        fileInput.value = "";
        updateSelectedFile();

        try {
            textarea.value = JSON.parse(
                sampleElement.textContent
            );
        } catch {
            textarea.value = "";
        }

        updateCharacterCount();
        activateInputMethod(0);
        textarea.focus();
    });

    textarea.addEventListener("input", () => {
        updateCharacterCount();

        if (textarea.value.trim()) {
            fileInput.value = "";
            updateSelectedFile();
        }
    });

    fileInput.addEventListener("change", () => {
        updateSelectedFile();

        if (fileInput.files.length) {
            textarea.value = "";
            updateCharacterCount();
        }
    });

    updateCharacterCount();
    updateSelectedFile();
    activateInputMethod(
        investigationForm.dataset.initialTab === "upload"
            ? 1
            : 0
    );

    document.querySelector(
        "[data-form-error-summary]"
    )?.focus();
})();
