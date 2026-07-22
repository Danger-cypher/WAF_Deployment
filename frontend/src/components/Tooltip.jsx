import { HelpCircle } from 'lucide-react';
import { useState, useRef, useEffect } from 'react';

const Tooltip = ({ text, children, position = 'top' }) => {
  const [isVisible, setIsVisible] = useState(false);
  const [actualPosition, setActualPosition] = useState(position);
  const tooltipRef = useRef(null);
  const triggerRef = useRef(null);

  useEffect(() => {
    if (isVisible && tooltipRef.current && triggerRef.current) {
      const tooltipRect = tooltipRef.current.getBoundingClientRect();
      const triggerRect = triggerRef.current.getBoundingClientRect();
      
      // Check if tooltip goes off screen and adjust position
      if (position === 'top' && tooltipRect.top < 0) {
        setActualPosition('bottom');
      } else if (position === 'bottom' && tooltipRect.bottom > window.innerHeight) {
        setActualPosition('top');
      } else if (position === 'left' && tooltipRect.left < 0) {
        setActualPosition('right');
      } else if (position === 'right' && tooltipRect.right > window.innerWidth) {
        setActualPosition('left');
      }
    }
  }, [isVisible, position]);

  return (
    <div className="tooltip-wrapper">
      <div
        ref={triggerRef}
        className="tooltip-trigger"
        onMouseEnter={() => setIsVisible(true)}
        onMouseLeave={() => setIsVisible(false)}
        onFocus={() => setIsVisible(true)}
        onBlur={() => setIsVisible(false)}
      >
        {children || <HelpCircle size={14} className="help-icon" />}
      </div>
      
      {isVisible && (
        <div 
          ref={tooltipRef}
          className={`tooltip-content ${actualPosition}`}
          role="tooltip"
        >
          {text}
          <div className="tooltip-arrow"></div>
        </div>
      )}
    </div>
  );
};

// Helper component for inline help text
export const HelpText = ({ children }) => {
  return (
    <Tooltip text={children}>
      <HelpCircle size={14} className="help-icon" />
    </Tooltip>
  );
};

export default Tooltip;
