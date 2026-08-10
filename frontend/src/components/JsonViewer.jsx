export default function HighlightedJson({ json }) {
  if (!json) return null;

  const jsonStr = JSON.stringify(json, null, 2);
  const lines = jsonStr.split('\n');

  const tokenizeLine = (line) => {
    const tokenRegex = /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?|[{}[\]:,]|\s+)/g;
    const matches = line.match(tokenRegex) || [line];

    return matches.map((token, index) => {
      let className = 'json-punctuation';
      if (/^"/.test(token)) {
        if (/:$/.test(token)) {
          className = 'json-key';
        } else {
          className = 'json-string';
        }
      } else if (/^(true|false)$/.test(token)) {
        className = 'json-boolean';
      } else if (/^null$/.test(token)) {
        className = 'json-null';
      } else if (/^-?\d+/.test(token)) {
        className = 'json-number';
      }

      return (
        <span key={index} className={className}>
          {token}
        </span>
      );
    });
  };

  return (
    <pre className="json-pre">
      <code>
        {lines.map((line, lineIndex) => (
          <div key={lineIndex} className="json-line">
            <span className="line-number">{lineIndex + 1}</span>
            <span className="line-content">{tokenizeLine(line)}</span>
          </div>
        ))}
      </code>
    </pre>
  );
}
