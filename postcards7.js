// Prevent browser auto-scroll from shifting the 3D coverflow layout
// when focus moves to elements inside perspective containers
window.addEventListener('scroll', function() {
    if (window.scrollX !== 0) window.scrollTo(0, window.scrollY);
});
document.addEventListener('scroll', function(e) {
    if (e.target !== document && e.target.scrollLeft) e.target.scrollLeft = 0;
}, true);

$(document).ready(function() {
if (window.HISTORIEK_IS_WORDPRESS) {
    document.querySelector('.nav-hamburger')?.remove();
    document.querySelector('.nav-bar')?.remove();
}
// Load concert data from external JSON file
const dataUrl = window.HISTORIEK_DATA_URL || 'concertData.json';
$.getJSON(dataUrl, function(data) {
    const concertData = data.concerts || data; // fallback if it's still just an array
    const headerData = data.header || {};

    if (headerData.h1) {
        $('#mainTitle').text(headerData.h1);
        document.title = headerData.h1 + ' - Alumni Arenbergconcert';
        // Also update aria-label if it's based on the title
    }
    if (headerData.swipe_hint) $('#swipeHintText').html(headerData.swipe_hint);

    // Reveal header once data is applied
    $('body').addClass('header-ready');

    // revert order
    concertData.reverse();


    const $wrapper = $('#coverflowWrapper');
    let currentIndex = 0;
    let totalCards = concertData.length;

    // Configuration: set to true to auto-flip the new card when swiping while flipped
    const autoFlipOnSwipe = false;

    // Generate postcard HTML
    function generatePostcard(concert, index) {
        const repertoireRaw = (concert.Repertoire || '').trim();
        const hasRepertoire = repertoireRaw.length > 0;
        const repertoireHtml = hasRepertoire
            ? repertoireRaw
                .split('\n')
                .map(item => item.trim())
                .filter(item => item !== '')
                .map(item => `<li>${item}</li>`)
                .join('')
            : '';

        const textHtml = concert.text
            ? concert.text.split('\n').filter(l => l.trim()).map(l => `<p>${l.trim()}</p>`).join('')
            : '';

        // Build images HTML: use images from concertData (max 4)
        const imgs = concert.images || [];
        let imagesHtml = '';
        const hasPostcardImage = !!concert.postcard_img;
        const concertDir = (concert.postcard_img || '').split('/')[0];
        const concertsBase = window.HISTORIEK_ASSETS_BASE_URL || 'concerts/';
        const imageBasePath = concertsBase + (concertDir ? concertDir + '/' : '');
        const maxThumbs = Math.min(imgs.length, 4);
        for (let i = 0; i < maxThumbs; i++) {
            const img = imgs[i];
            const thumbSrc = imageBasePath + (img.thumb || img);
            const fullSrc = imageBasePath + (img.full || img);
            const imgAlt = img.alt || (concert.title + ' foto ' + (i+1));
            imagesHtml += `<img class="concert-img" src="${thumbSrc}" data-full="${fullSrc}" alt="${imgAlt}" role="button" tabindex="-1">`;
        }

        return `
            <div class="postcard" data-index="${index}" data-season="${concert.season}" data-year="${concert.year}" role="group" aria-roledescription="slide" aria-label="${concert.title} - ${concert.year}">
                <div class="postcard-inner">
                    <div class="postcard-front">
                        ${hasPostcardImage ? `<img src="${concertsBase}${concert.postcard_img}" alt="${concert.title}">` : ''}
                        ${!hasPostcardImage ? `<div class="postcard-front-overlay">
                            <span class="postcard-year">${concert.dates || concert.year}</span>
                            <h3 class="postcard-title-front">${concert.title}</h3>
                        </div>` : ''}
                        <div class="flip-icon" aria-hidden="true">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"></path>
                                <path d="M3 3v5h5"></path>
                            </svg>
                        </div>
                    </div>
                    <div class="postcard-back">
                        <button class="card-close-btn" aria-label="Kaart terugdraaien" title="Terugdraaien">&times;</button>
                        <div class="postcard-back-content">
                            <div class="postcard-back-left${textHtml && concert.text.trim().length >= 50 ? ' equal-heights' : ''}">
                                ${textHtml ? `<div class="postcard-back-text" data-custom-scroll>${textHtml}</div><div class="text-repertoire-spacer"></div>` : ''}
                                ${hasRepertoire && repertoireHtml ? `<h3 class="postcard-back-repertoire-label">Repertoire</h3>
                                <div class="postcard-back-repertoire" data-custom-scroll><ul>${repertoireHtml}</ul></div>` : ''}
                                <div class="postcard-back-bottom-row">
                                    ${concert.director ? `<div class="postcard-back-director">
                                        <dl><dt>Dirigent</dt>
                                        <dd>${concert.director}</dd></dl>
                                    </div>` : ''}
                                    ${concert.coorporation ? `<div class="postcard-back-coorporation">
                                        <dl><dt>${concert.coorporation_label || 'Medewerking'}</dt>
                                        <dd>${concert.coorporation}</dd></dl>
                                    </div>` : ''}
                                </div>
                            </div>
                            <div class="postcard-back-right">
                                <div class="postmark-wrapper">
                                    <div class="postmark-cancel"></div>
                                    <div class="postmark">
                                        <span class="postmark-city">LEUVEN</span>
                                        <span class="postmark-year">${concert.year}</span>
                                    </div>
                                </div>
                                <div class="postcard-back-title">${concert.title}</div>
                                <div class="postcard-back-date">${[concert.dates, concert.year].filter(Boolean).join(' ')}${concert.locations ? ' - ' + concert.locations : ''}</div>
                                <div class="postcard-back-images">
                                    ${imagesHtml}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    // Initialize postcards
    concertData.forEach((concert, index) => {
        $wrapper.append(generatePostcard(concert, index));
    });

    // Add initial hidden state for fade-in
    $('.postcard').addClass('fade-in-init');

    // Fade in cards with staggered delay after initial layout
    requestAnimationFrame(() => {
        const cards = document.querySelectorAll('.postcard');
        cards.forEach((card, i) => {
            const delay = Math.min(i * 60, 400);
            setTimeout(() => {
                card.classList.add('fade-in-ready');
                card.classList.remove('fade-in-init');
            }, delay);
        });
        // Remove fade-in transition override after animation completes
        setTimeout(() => {
            cards.forEach(card => card.classList.remove('fade-in-ready'));
        }, 1200);
    });

    // Helper: toggle tabindex on concert images when card is flipped/unflipped
    function updateFlippedImageTabindex($card) {
        const isFlipped = $card.hasClass('flipped');
        $card.find('.concert-img[role="button"]').attr('tabindex', isFlipped ? '0' : '-1');
    }

    // History debounce timer
    let historyTimer = null;
    // Rapid navigation state
    let rapidNavTimer = null;

    // Cache postcard DOM elements once after they're created
    let postcardEls = null;
    function getPostcardEls() {
        if (!postcardEls) {
            postcardEls = document.querySelectorAll('.postcard');
        }
        return postcardEls;
    }

    // Helper: responsive card spacing based on viewport height
    function getCardSpacingByViewport(vh) {
        if (vh <= 550) return 120; // Tight, overlapping
        if (vh <= 650) return 200;
        if (vh <= 800) return 280;
        return 350;
    }

    // Helper: get postcard element by index
    function getCardByIndex(index) {
        return $(`.postcard[data-index="${index}"]`);
    }

    // Helper: get focused postcard
    function getFocusedCard() {
        return $('.postcard.focused');
    }

    // Helper: check flipped state on a card
    function isCardFlipped($card) {
        return $card.length && $card.hasClass('flipped');
    }

    // Helper: clamp index to valid range
    function clampIndex(index) {
        return Math.max(0, Math.min(totalCards - 1, index));
    }

    // Helper: apply card flip state and sync dependent UI state
    function setCardFlippedState($card, isFlipped, syncHash) {
        if (!$card || !$card.length) return;
        $card.toggleClass('flipped', !!isFlipped);
        updateFlippedImageTabindex($card);
        updateLabelVisibility();
        if (syncHash) updateHash();
    }

    // Helper: move one card in a direction
    function navigateByDirection(direction) {
        if (direction === 'next') {
            goNext();
        } else {
            goPrev();
        }
    }

    // Helper: move according to delta direction, respecting flipped behavior
    function navigateByDelta(delta) {
        const direction = delta > 0 ? 'next' : 'prev';
        const $focusedCard = getFocusedCard();
        if (isCardFlipped($focusedCard)) {
            navigateWhileFlipped(direction);
        } else {
            navigateByDirection(direction);
        }
    }

    // Position postcards in coverflow style
    function updateCoverflow() {
        const cards = getPostcardEls();
        const len = cards.length;
        // Only update cards within visible range (±6), skip far-away ones
        const visibleRange = 6;
        
        // Responsive spacing based on viewport height
        const cardSpacing = getCardSpacingByViewport(window.innerHeight);

        for (let i = 0; i < len; i++) {
            const el = cards[i];
            const offset = i - currentIndex;
            const absOffset = Math.abs(offset);

            // Hide far-away cards immediately and skip expensive work
            if (absOffset > visibleRange) {
                el.style.opacity = '0';
                el.style.pointerEvents = 'none';
                el.style.zIndex = '0';
                el.setAttribute('aria-hidden', 'true');
                el.classList.remove('focused');
                continue;
            }

            // Calculate transform values
            let translateX = offset * cardSpacing;
            let translateZ = -absOffset * 50;
            let rotateY = offset < 0 ? 30 : (offset > 0 ? -30 : 0);
            let scale = offset === 0 ? 1 : Math.max(0.75, 0.9 - (absOffset * 0.05));
            let opacity = absOffset > 4 ? 0 : Math.max(0.5, 1 - (absOffset * 0.1));
            let zIndex = 100 - absOffset;

            if (offset === 0) {
                rotateY = 0;
                translateX = 0;
                translateZ = 0;
            }

            // Write all style properties in one batch via direct DOM
            const s = el.style;
            s.transform = `translateX(${translateX}px) translateZ(${translateZ}px) rotateY(${rotateY}deg) scale(${scale})`;
            s.opacity = opacity;
            s.zIndex = zIndex;
            s.pointerEvents = absOffset <= 4 ? 'auto' : 'none';
            // CSS custom props for hover state
            s.setProperty('--tx', `${translateX}px`);
            s.setProperty('--tz', `${translateZ}px`);
            s.setProperty('--ry', `${rotateY}deg`);
            s.setProperty('--scale', scale);

            // Toggle focused class and ARIA state
            if (offset === 0) {
                el.classList.add('focused');
                el.setAttribute('aria-hidden', 'false');
            } else {
                el.classList.remove('focused');
                el.classList.remove('flipped');
                el.setAttribute('aria-hidden', absOffset > 4 ? 'true' : 'false');
            }
        }

        // Hide nav buttons at edges
        $('#prevBtn').toggle(currentIndex > 0);
        $('#nextBtn').toggle(currentIndex < totalCards - 1);

        // Update focused label with season and year
        const currentConcert = concertData[currentIndex];
        const focusedLabel = document.getElementById('focusedLabel');
        if (focusedLabel && currentConcert) {
            focusedLabel.textContent = currentConcert.season + ' ' + currentConcert.year;
        }
        updateLabelVisibility();

        // Update screen reader announcement
        const announcer = document.getElementById('concertAnnouncer');
        if (announcer) {
            announcer.textContent = currentConcert.title + ', ' + currentConcert.year + ' (' + (currentIndex + 1) + ' van ' + totalCards + ')';
        }

        // Debounce URL hash update to avoid micro-hangs during rapid navigation
        if (historyTimer) clearTimeout(historyTimer);
        historyTimer = setTimeout(() => {
            updateHash();
        }, 150);
    }

    // Helper: update URL hash including flip state
    function updateHash() {
        const slug = concertData[currentIndex].slug;
        const $fc = getCardByIndex(currentIndex);
        const isFlipped = isCardFlipped($fc);
        const hash = '#' + slug + (isFlipped ? '/flipped' : '');
        // Use explicit path so <base href> never leaks plugin filesystem URL in browser bar.
        const cleanUrl = window.location.pathname + window.location.search + hash;
        history.replaceState(null, null, cleanUrl);
    }

    // Helper: show/hide label based on focused card flip state
    function updateLabelVisibility() {
        const $focusedCard = getCardByIndex(currentIndex);
        const focusedLabel = document.getElementById('focusedLabel');
        if (focusedLabel) {
            if (isCardFlipped($focusedCard)) {
                focusedLabel.classList.add('hidden');
            } else {
                focusedLabel.classList.remove('hidden');
            }
        }
    }

    // Navigate to specific index
    function goToIndex(index) {
        currentIndex = clampIndex(index);
        updateCoverflow();
    }

    // Navigate previous
    function goPrev() {
        if (currentIndex > 0) {
            currentIndex--;
            updateCoverflow();
        }
    }

    // Navigate next
    function goNext() {
        if (currentIndex < totalCards - 1) {
            currentIndex++;
            updateCoverflow();
        }
    }

    // Event listeners
    $('#prevBtn').on('click', function(e) {
        e.stopPropagation();
        const $focusedCard = getFocusedCard();
        if (isCardFlipped($focusedCard)) return navigateWhileFlipped('prev');
        goPrev();
    });
    $('#nextBtn').on('click', function(e) {
        e.stopPropagation();
        const $focusedCard = getFocusedCard();
        if (isCardFlipped($focusedCard)) return navigateWhileFlipped('next');
        goNext();
    });

    // Click handler using manual hit detection for better 3D support
    let lightboxOpen = false;
    $('.coverflow-container').on('click', function(e) {
        // Don't handle clicks on navigation buttons or card close button
        if ($(e.target).closest('.coverflow-nav, .card-close-btn').length) return;
        // Don't flip card if lightbox is open or click came from an image/lightbox
        if (lightboxOpen) return;
        if ($(e.target).closest('.postcard-back-images').length) return;

        const containerRect = this.getBoundingClientRect();
        const clickX = e.clientX - containerRect.left;
        const centerX = containerRect.width / 2;
        const focusedCardEl = getFocusedCard()[0];
        const cardWidth = focusedCardEl ? focusedCardEl.getBoundingClientRect().width : 450;
        const deadZone = cardWidth / 2; // The center area where clicks go to focused card

        // Get all postcards at this click point
        const elements = document.elementsFromPoint(e.clientX, e.clientY);
        let clickedPostcard = null;
        
        // Find all postcards at this point and pick the best one
        for (const el of elements) {
            if (el.classList.contains('postcard')) {
                clickedPostcard = el;
                break;
            }
            // Also check parent
            const parent = el.closest('.postcard');
            if (parent) {
                clickedPostcard = parent;
                break;
            }
        }

        let targetIndex;
        
        if (clickedPostcard) {
            targetIndex = parseInt(clickedPostcard.dataset.index, 10);
        } else {
            // Fallback: calculate based on X position relative to center
            const offsetFromCenter = clickX - centerX;
            
            if (Math.abs(offsetFromCenter) < deadZone) {
                // Click in center area - target the focused card
                targetIndex = currentIndex;
            } else {
                // Click on side - navigate in that direction
                targetIndex = offsetFromCenter > 0 ? currentIndex + 1 : currentIndex - 1;
            }
        }

        // Clamp to valid range
        targetIndex = clampIndex(targetIndex);

        if (targetIndex === currentIndex) {
            // Focused card - flip it
            const $currentCard = getCardByIndex(currentIndex);
            setCardFlippedState($currentCard, !$currentCard.hasClass('flipped'), true);
        } else {
            // Navigate to clicked card
            goToIndex(targetIndex);
        }
    });

    // Card close button click handler (unflip card)
    $(document).on('click', '.card-close-btn', function(e) {
        e.stopPropagation();
        const $card = $(this).closest('.postcard');
        setCardFlippedState($card, false, true);
    });

    // Helper: navigate while flipped — unflip current, move, auto-flip new card
    let flipAfterNavTimer = null;
    function navigateWhileFlipped(direction, skipReflip) {
        const canGo = direction === 'next' ? currentIndex < totalCards - 1 : currentIndex > 0;
        if (!canGo) return;
        // Cancel any pending auto-flip from a previous call
        if (flipAfterNavTimer) { clearTimeout(flipAfterNavTimer); flipAfterNavTimer = null; }
        setCardFlippedState(getFocusedCard(), false, false);
        navigateByDirection(direction);
        // Only auto-flip the new card if this is a single-step navigation (not held key) and autoFlipOnSwipe is enabled
        if (!skipReflip && autoFlipOnSwipe) {
            flipAfterNavTimer = setTimeout(function() {
                const $fc = getFocusedCard();
                setCardFlippedState($fc, true, false);
                flipAfterNavTimer = null;
                updateHash();
            }, 650);
        }
    }

    // Keyboard navigation — throttled via requestAnimationFrame for smooth held-key scrolling
    let navRafPending = false;
    let pendingNavAction = null;
    let wasFlippedBeforeHold = false; // tracks if we were flipped when key-hold started

    function enterRapidNav() {
        $wrapper.addClass('rapid-nav');
        if (rapidNavTimer) clearTimeout(rapidNavTimer);
        rapidNavTimer = setTimeout(() => {
            $wrapper.removeClass('rapid-nav');
        }, 300);
    }

    $(document).on('keydown', function(e) {
        if (lightboxOpen) return;

        if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
            e.preventDefault();

            const isRepeat = e.repeat;
            if (isRepeat) {
                enterRapidNav();
            } else {
                // First keydown — remember if currently flipped
                wasFlippedBeforeHold = isCardFlipped(getFocusedCard());
            }

            // Store the desired action; only schedule one rAF at a time
            pendingNavAction = { key: e.key, repeat: isRepeat };
            if (!navRafPending) {
                navRafPending = true;
                requestAnimationFrame(function() {
                    navRafPending = false;
                    const action = pendingNavAction;
                    pendingNavAction = null;
                    if (!action) return;

                    const flipped = isCardFlipped(getFocusedCard());
                    const dir = action.key === 'ArrowLeft' ? 'prev' : 'next';

                    if (flipped || wasFlippedBeforeHold) {
                        // Holding key: just unflip & scroll, don't re-flip
                        navigateWhileFlipped(dir, action.repeat);
                    } else {
                        navigateByDirection(dir);
                    }
                });
            }
        } else if (e.key === ' ' || e.key === 'Enter') {
            e.preventDefault();
            const $focusedCard = getFocusedCard();
            setCardFlippedState($focusedCard, !$focusedCard.hasClass('flipped'), true);
        }
    });

    // When the user releases the arrow key after holding while flipped, auto-flip the new card
    $(document).on('keyup', function(e) {
        if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
            if (wasFlippedBeforeHold) {
                // Small delay so the last coverflow slide settles
                if (flipAfterNavTimer) clearTimeout(flipAfterNavTimer);
                flipAfterNavTimer = setTimeout(function() {
                    const $fc = getFocusedCard();
                    setCardFlippedState($fc, true, false);
                    flipAfterNavTimer = null;
                    updateHash();
                }, 400);
            }
            wasFlippedBeforeHold = false;
        }
    });

    // Touch/swipe support
    let touchStartX = 0;
    let touchEndX = 0;
    let touchInsideScroll = false;
    let lastSwipeTime = 0;
    const swipeCooldown = 500; // ms between swipe navigations

    $wrapper.on('touchstart', function(e) {
        const t = e.originalEvent.changedTouches[0];
        touchStartX = t.screenX;
        // Check if the touch started inside a custom-scroll-content
        touchInsideScroll = !!($(e.target).closest('.custom-scroll-content').length);
    });

    $wrapper.on('touchend', function(e) {
        touchEndX = e.originalEvent.changedTouches[0].screenX;
        handleSwipe();
    });

    function handleSwipe() {
        // Don't navigate cards while lightbox is open
        if (lightboxOpen) return;
        // If the touch originated inside a scrollable area, don't navigate
        if (touchInsideScroll) return;
        // Cooldown to prevent skipping cards on hard swipes
        const now = Date.now();
        if (now - lastSwipeTime < swipeCooldown) return;
        
        const swipeThreshold = 50;
        const diff = touchStartX - touchEndX;

        if (Math.abs(diff) > swipeThreshold) {
            lastSwipeTime = now;
            navigateByDelta(diff);
        }
    }

    // Wheel/trackpad scroll support
    let lastWheelTime = 0;
    const wheelCooldown = 500; // ms between card changes (increase to prevent skipping cards on hard swipes)

    // Scroll-lock: when the user scrolls inside a custom-scroll area,
    // block ALL card navigation (including accidental horizontal leakage)
    // for a grace period after the last scroll event inside that area.
    let scrollLockUntil = 0;
    const scrollLockGrace = 400; // ms

    $wrapper.on('wheel', function(e) {
        // If the wheel event originates inside a scrollable custom area,
        // let it scroll that content instead of navigating cards.
        const $scrollContent = $(e.target).closest('.custom-scroll-content');
        if ($scrollContent.length) {
            const el = $scrollContent[0];
            if (el.scrollHeight > el.clientHeight) {
                const atTop = el.scrollTop <= 0 && e.originalEvent.deltaY < 0;
                const atBottom = (el.scrollTop + el.clientHeight >= el.scrollHeight - 1) && e.originalEvent.deltaY > 0;
                if (!atTop && !atBottom) {
                    // Refresh the scroll lock timer
                    scrollLockUntil = Date.now() + scrollLockGrace;
                    return;  // let content scroll, don't navigate
                }
            }
            // Even at edges, refresh lock to avoid accidental horizontal nav
            scrollLockUntil = Date.now() + scrollLockGrace;
        }

        // If scroll lock is active, eat the event entirely
        if (Date.now() < scrollLockUntil) {
            e.preventDefault();
            return;
        }

        // Prevent page scroll
        e.preventDefault();
        
        const now = Date.now();
        if (now - lastWheelTime < wheelCooldown) return;
        
        // Use deltaX for horizontal scroll, fallback to deltaY
        const delta = Math.abs(e.originalEvent.deltaX) > Math.abs(e.originalEvent.deltaY) 
            ? e.originalEvent.deltaX 
            : e.originalEvent.deltaY;
        
        if (Math.abs(delta) > 10) {
            lastWheelTime = now;
            navigateByDelta(delta);
        }
    });

    // Keyboard activation for concert images (Enter/Space opens lightbox)
    $(document).on('keydown', '.concert-img[role="button"]', function(e) {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            $(this).trigger('click');
        }
    });

    // ── Lightbox for concert images ──
    $(document).on('click', '.postcard-back-images .concert-img', function(e) {
        e.stopPropagation();
        e.preventDefault();
        lightboxOpen = true;

        // Collect all images in the same card's back
        const $allImgs = $(this).closest('.postcard-back-images').find('.concert-img');
        let lightboxIndex = $allImgs.index(this);

        // Build the overlay
        const $triggerEl = $(this).closest('.postcard');
        const $overlay = $('<div class="lightbox-overlay" role="dialog" aria-modal="true" aria-label="Foto weergave"></div>');
        const $wrapper = $('<div class="lightbox-content"></div>');
        const $img = $('<img class="lightbox-img" alt="">');
        const $closeBtn = $('<button class="lightbox-close-btn" aria-label="Sluiten" title="Sluiten">&times;</button>');
        const $prevBtn = $('<button class="lightbox-nav-btn prev" aria-label="Vorige foto" title="Vorige">&#8249;</button>');
        const $nextBtn = $('<button class="lightbox-nav-btn next" aria-label="Volgende foto" title="Volgende">&#8250;</button>');
        $wrapper.append($img).append($prevBtn).append($nextBtn).append($closeBtn);
        $overlay.append($wrapper);
        $('body').append($overlay);

        // Trap focus within the lightbox dialog
        $overlay.on('keydown.lightboxTrap', function(e) {
            if (e.key === 'Tab') {
                const focusable = $overlay.find('button:visible');
                const first = focusable.first()[0];
                const last = focusable.last()[0];
                if (e.shiftKey && document.activeElement === first) {
                    e.preventDefault();
                    last.focus();
                } else if (!e.shiftKey && document.activeElement === last) {
                    e.preventDefault();
                    first.focus();
                }
            }
        });

        function showImage(idx) {
            const $target = $allImgs.eq(idx);
            const thumbSrc = $target.attr('src');
            const fullSrc = $target.data('full') || thumbSrc;
            $img.attr('src', thumbSrc);
            $img.attr('alt', $target.attr('alt') || 'Concert foto ' + (idx + 1));
            // Preload and swap to full-res if available
            if (fullSrc !== thumbSrc) {
                const preload = new Image();
                preload.onload = function() { $img.attr('src', fullSrc); };
                preload.src = fullSrc;
            }
            // Hide/show nav buttons at boundaries
            const hasMultiple = $allImgs.length > 1;
            $prevBtn.toggle(hasMultiple);
            $nextBtn.toggle(hasMultiple);
        }

        showImage(lightboxIndex);
        $closeBtn.focus();

        function closeLightbox() {
            $overlay.off('keydown.lightboxTrap');
            $overlay.remove();
            lightboxOpen = false;
            $(document).off('keydown.lightbox');
            if ($triggerEl && $triggerEl.length) $triggerEl.focus();
        }

        let suppressCloseUntil = 0;

        function bindLightboxButton($btn, action, opts) {
            const shouldSuppressClose = opts && opts.suppressClose;
            // Handle touch directly so fast double taps don't trigger browser zoom.
            $btn.on('touchend', function(e) {
                e.preventDefault();
                e.stopPropagation();
                if (shouldSuppressClose) suppressCloseUntil = Date.now() + 500;
                action();
            });
            $btn.on('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                if (shouldSuppressClose) suppressCloseUntil = Date.now() + 500;
                action();
            });
        }

        bindLightboxButton($closeBtn, closeLightbox);
        $img.on('click', function(e) {
            e.stopPropagation();
            if (Date.now() < suppressCloseUntil) return;
            closeLightbox();
        });
        bindLightboxButton($prevBtn, function() {
            lightboxIndex = (lightboxIndex - 1 + $allImgs.length) % $allImgs.length;
            showImage(lightboxIndex);
        }, { suppressClose: true });
        bindLightboxButton($nextBtn, function() {
            lightboxIndex = (lightboxIndex + 1) % $allImgs.length;
            showImage(lightboxIndex);
        }, { suppressClose: true });
        $overlay.on('click', function(e) {
            if (Date.now() < suppressCloseUntil) return;
            if ($(e.target).hasClass('lightbox-overlay')) closeLightbox();
        });
        $(document).on('keydown.lightbox', function(e) {
            if (e.key === 'Escape') closeLightbox();
            if (e.key === 'ArrowLeft') { lightboxIndex = (lightboxIndex - 1 + $allImgs.length) % $allImgs.length; showImage(lightboxIndex); }
            if (e.key === 'ArrowRight') { lightboxIndex = (lightboxIndex + 1) % $allImgs.length; showImage(lightboxIndex); }
        });

        // Touch swipe support for lightbox on mobile
        let lbTouchStartX = 0;
        let lbTouchStartY = 0;
        $overlay.on('touchstart', function(e) {
            lbTouchStartX = e.originalEvent.changedTouches[0].screenX;
            lbTouchStartY = e.originalEvent.changedTouches[0].screenY;
        });
        $overlay.on('touchmove', function(e) {
            e.preventDefault(); // prevent page scroll while swiping in lightbox
        });
        $overlay.on('touchend', function(e) {
            const endX = e.originalEvent.changedTouches[0].screenX;
            const endY = e.originalEvent.changedTouches[0].screenY;
            const diffX = lbTouchStartX - endX;
            const diffY = lbTouchStartY - endY;
            // Only handle horizontal swipes (not taps or vertical scrolls)
            if (Math.abs(diffX) > 50 && Math.abs(diffX) > Math.abs(diffY)) {
                lightboxIndex = diffX > 0
                    ? (lightboxIndex + 1) % $allImgs.length
                    : (lightboxIndex - 1 + $allImgs.length) % $allImgs.length;
                showImage(lightboxIndex);
            }
        });
    });

    // Read initial card from URL hash (slug-based, with optional /flipped suffix)
    const hash = window.location.hash.replace('#', '');
    let initialFlipped = false;
    if (hash) {
        const parts = hash.split('/');
        const slug = parts[0];
        initialFlipped = parts[1] === 'flipped';
        const idx = concertData.findIndex(c => c.slug === slug);
        if (idx !== -1) {
            currentIndex = idx;
        }
    }

    // ── Custom scrollbar implementation ──
    function initCustomScrollbars() {
        $('[data-custom-scroll]').each(function() {
            const $container = $(this);
            if ($container.find('.custom-scroll-wrapper').length) return; // already init

            // Wrap inner content
            const inner = $container.html();
            $container.html(
                '<div class="custom-scroll-wrapper">' +
                    '<div class="custom-scroll-content">' + inner + '</div>' +
                    '<div class="custom-scroll-track"><div class="custom-scroll-thumb"></div></div>' +
                '</div>'
            );

            const $wrapper  = $container.find('.custom-scroll-wrapper');
            const $content  = $container.find('.custom-scroll-content');
            const $track    = $container.find('.custom-scroll-track');
            const $thumb    = $container.find('.custom-scroll-thumb');

            function updateThumb() {
                const ch = $content[0].clientHeight;
                const sh = $content[0].scrollHeight;
                if (sh <= ch) {
                    $track.addClass('hidden');
                    $thumb.addClass('hidden');
                    return;
                }
                $track.removeClass('hidden');
                $thumb.removeClass('hidden');
                const ratio = ch / sh;
                const thumbH = Math.max(18, $track.height() * ratio);
                const scrollFrac = $content[0].scrollTop / (sh - ch);
                const thumbTop = scrollFrac * ($track.height() - thumbH);
                $thumb.css({ height: thumbH + 'px', top: thumbTop + 'px' });
            }

            $content.on('scroll', updateThumb);

            // Drag support
            let dragging = false, startY = 0, startScrollTop = 0;

            $thumb.on('mousedown', function(e) {
                e.preventDefault();
                e.stopPropagation();
                dragging = true;
                startY = e.clientY;
                startScrollTop = $content[0].scrollTop;
                $thumb.addClass('dragging');
            });

            $(document).on('mousemove.customscroll', function(e) {
                if (!dragging) return;
                e.preventDefault();
                const sh = $content[0].scrollHeight;
                const ch = $content[0].clientHeight;
                const trackH = $track.height();
                const thumbH = $thumb.height();
                const dy = e.clientY - startY;
                const scrollRange = sh - ch;
                const trackRange = trackH - thumbH;
                $content[0].scrollTop = startScrollTop + (dy / trackRange) * scrollRange;
            });

            $(document).on('mouseup.customscroll', function() {
                if (dragging) {
                    dragging = false;
                    $thumb.removeClass('dragging');
                }
            });

            // Click on track to jump
            $track.on('click', function(e) {
                e.stopPropagation();
                const trackRect = $track[0].getBoundingClientRect();
                const clickY = e.clientY - trackRect.top;
                const ratio = clickY / $track.height();
                const sh = $content[0].scrollHeight;
                const ch = $content[0].clientHeight;
                $content[0].scrollTop = ratio * (sh - ch);
            });

            // Observe size changes
            if (window.ResizeObserver) {
                new ResizeObserver(updateThumb).observe($content[0]);
            }

            // Initial update after a small delay (card might not be visible yet)
            setTimeout(updateThumb, 100);
        });
    }

    // Re-init scrollbars whenever a card is flipped
    $(document).on('transitionend', '.postcard-inner', function() {
        setTimeout(initCustomScrollbars, 50);
    });

    // Compute flip scale so flipped card fits within viewport
    function updateFlipDimensions() {
        const vw = window.innerWidth;
        const vh = window.innerHeight;
        
        // Detect mobile device (touch-enabled)
        const isMobile = ('ontouchstart' in window) || (navigator.maxTouchPoints > 0);

        // Back content dimensions based on current CSS breakpoint
        // These are what actually need to fit when flipped (rotated 90deg)
        let backW, backH;
        if (vh <= 550) {
            // Very short viewport
            backW = 260; backH = 180;
        } else if (vh <= 650) {
            backW = 400; backH = 280;
        } else if (vh <= 800) {
            backW = 520; backH = 380;
        } else if (vw <= 768) {
            // Mobile: back content is 400x280
            backW = 400; backH = 280;
        } else if (vw <= 1200) {
            backW = 550; backH = 380;
        } else {
            backW = 623; backH = 450;
        }

        const perspective = 1200;
        const padding = 0.88; // More conservative padding
        const headerH = vh <= 550 ? 60 : (vh <= 650 ? 100 : (vh <= 800 ? 140 : 120));

        // On small screens, reduce translateZ to avoid excessive perspective magnification
        let flipTZ = (vw <= 768 || vh <= 650) ? 0 : (vw <= 1200 ? 150 : 300);
        const perspFactor = perspective / (perspective - flipTZ);

        const availW = vw * padding;
        const availH = (vh - headerH) * padding;

        // After rotateZ(90deg): visual width = backW, visual height = backH
        // But we need to flip these because of the 90deg rotation
        const scaleForW = availW / (backH * perspFactor);  // backH becomes visual width
        const scaleForH = availH / (backW * perspFactor);  // backW becomes visual height
        
        let flipScale;
        if (isMobile) {
            // Mobile: use calculated scale to fit viewport
            let maxScale;
            if (vh <= 550) {
                maxScale = 1.6;
            } else if (vh <= 650) {
                maxScale = 1.4;
            } else {
                maxScale = 1.0;
            }
            flipScale = Math.min(maxScale, scaleForW, scaleForH);
        } else {
            // Desktop: scale based on window size with smooth transitions
            if (vh <= 550) {
                // Very small: 2.0x
                flipScale = 2.0;
            } else if (vh <= 655) {
                // Small-medium: 1.6x
                flipScale = 1.6;
            } else if (vh <= 761) {
                // Medium: 1.2x
                flipScale = 1.2;
            } else if (vh <= 900) {
                // Medium-large: 1.5x
                flipScale = 1.5;
            } else {
                // Large desktop window: use calculated scale capped at 1.3x
                flipScale = Math.min(1.3, scaleForW, scaleForH);
            }
        }
        
        console.log('Flip dimensions calc:', {
            vw, vh,
            isMobile,
            backW, backH,
            availW: availW.toFixed(0), 
            availH: availH.toFixed(0),
            perspFactor: perspFactor.toFixed(2),
            scaleForW: scaleForW.toFixed(2),
            scaleForH: scaleForH.toFixed(2),
            finalScale: flipScale.toFixed(2)
        });

        const finalScale = Math.max(0.9, flipScale);
        document.documentElement.style.setProperty('--flip-scale', finalScale);
        document.documentElement.style.setProperty('--flip-tz', flipTZ + 'px');

        // At 1.6 scale with zero Z-translation, keep the focused label below the poster.
        const needsBelowCardLabel = Math.abs(finalScale - 1.6) < 0.001 && flipTZ === 0;
        document.body.classList.toggle('focused-label-below-card', needsBelowCardLabel);
        
    }

    // Update flip dimensions on resize
    $(window).on('resize', function() {
        updateFlipDimensions();
        updateCoverflow(); // Update card spacing for responsive layout
    });
    updateFlipDimensions();

    // Initialize coverflow
    updateCoverflow();

    // If the hash indicated flipped state, flip the focused card after rendering
    if (initialFlipped) {
        setTimeout(function() {
            const $card = $(`.postcard[data-index="${currentIndex}"]`);
            $card.addClass('flipped');
            updateFlippedImageTabindex($card);
            updateLabelVisibility();
        }, 100);
    }
}).fail(function() {
    // Reveal header even on failure to show hardcoded text
    $('body').addClass('header-ready');
}); // end $.getJSON
}); // end document.ready
