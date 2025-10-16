package logx

import (
	"fmt"
	"time"
)

// FormatDuration convierte una duración a formato human-friendly
// Ejemplos: 18.9s, 1m14.4s, 2h30m
func FormatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%.0fms", d.Seconds()*1000)
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	if d < time.Hour {
		minutes := int(d.Minutes())
		seconds := d.Seconds() - float64(minutes*60)
		return fmt.Sprintf("%dm%.1fs", minutes, seconds)
	}
	hours := int(d.Hours())
	remainder := d - time.Duration(hours)*time.Hour
	minutes := int(remainder.Minutes())
	return fmt.Sprintf("%dh%dm", hours, minutes)
}

// ShortID genera IDs cortos basados en tipo y número
// Ejemplos: cmd#A3, grp#S1
func ShortID(prefix string, id int64) string {
	if id == 0 {
		return ""
	}
	// Convertir a base26 para caracteres
	chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	num := int(id % 26)
	suffix := int(id / 26)
	if suffix == 0 {
		return fmt.Sprintf("%s#%c%d", prefix, chars[num], id)
	}
	return fmt.Sprintf("%s#%c%d", prefix, chars[num], suffix)
}
